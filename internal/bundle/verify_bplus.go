package bundle

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/identity"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
)

const (
	verdictPass          = "PASS"
	verdictFail          = "FAIL"
	verdictIndeterminate = "INDETERMINATE"
	verdictNotChecked    = "NOT_CHECKED"
)

func newBPlusResult() Result {
	return Result{
		BundleVersion: bPlusManifestVersion, Checks: []string{}, SigningKeyIDs: []string{},
		Signature: verdictNotChecked, BundleLedgerIntegrity: verdictNotChecked,
		IdentityContinuity: verdictNotChecked, LifecycleChain: verdictNotChecked,
		SigningKeyStatus: verdictNotChecked, EpochAuthorization: verdictNotChecked,
		EvidenceAnchor: verdictNotChecked, CheckpointAuthenticity: verdictNotChecked,
		CheckpointSource: verdictNotChecked, CheckpointSequence: verdictNotChecked,
		CheckpointFreshness: verdictNotChecked, EvidenceTimeAssurance: "HOST_METADATA_ONLY",
		OverallTrust: OverallInvalid,
	}
}

func failBPlus(code, format string, args ...any) Result {
	res := newBPlusResult()
	res.OK = false
	res.ReasonCode = code
	res.Reason = fmt.Sprintf(format, args...)
	res.OverallTrust = OverallInvalid
	return res
}

func notTrustedBPlus(res Result, code, format string, args ...any) Result {
	res.OK = false
	res.ReasonCode = code
	res.Reason = fmt.Sprintf(format, args...)
	res.OverallTrust = OverallNotTrusted
	return res
}

func verifyBPlusBundle(members map[string][]byte, manifest manifestDocument, options Options) Result {
	res := newBPlusResult()
	res.Checks = append(res.Checks, "B+ manifest matches every declared member byte")
	if options.ExpectedKeyID != "" {
		return notTrustedBPlus(res, "BPLUS_REQUIRES_IDENTITY_PIN", "B+ verification requires --expected-identity-id, not a legacy operational-key pin")
	}
	embeddedState, embeddedAnchor, authorityResult := parseBPlusAuthority(members)
	if !authorityResult.OK {
		return authorityResult
	}
	res.IdentityID = embeddedState.Genesis.IdentityID
	res.LifecycleSequence = embeddedState.LastSequence
	res.LifecycleDigest = embeddedState.LastRecordDigest
	if manifest.IdentityID != res.IdentityID || manifest.CheckpointSequence == nil || *manifest.CheckpointSequence != res.LifecycleSequence ||
		manifest.CheckpointDigest != res.LifecycleDigest || manifest.EvidenceAnchorDigest != embeddedAnchor.AnchorDigest {
		return failBPlus("MANIFEST_AUTHORITY_MISMATCH", "manifest authority fields do not match the authenticated B+ members")
	}
	res.LifecycleChain = verdictPass
	res.CheckpointAuthenticity = verdictPass
	res.CheckpointSequence = verdictPass
	res.Checks = append(res.Checks, "genesis and lifecycle signatures, links, sequence, policy, and proofs verified")

	trust, trustResult := loadTrustRoots(members, false)
	if !trustResult.OK {
		return failBPlus("TRUST_ROOTS_INVALID", "%s", trustResult.Reason)
	}
	if revoked, err := parseRevocations(members["revocations.json"]); err != nil || len(revoked) != 0 {
		return failBPlus("LEGACY_REVOCATION_CONFLICT", "B+ revocations.json must be an empty compatibility member; lifecycle records are authoritative")
	}
	if err := exactLifecycleTrust(trust, embeddedState.Trust); err != nil {
		return failBPlus("TRUST_ROOT_SUBSTITUTION", "%v", err)
	}

	bundleSigner, sealResult := verifyBundleSeal(members, trust)
	if !sealResult.OK {
		return failBPlus("BUNDLE_SEAL_INVALID", "%s", sealResult.Reason)
	}
	receipts, receiptResult := parseReceipts(members)
	if !receiptResult.OK {
		return failBPlus("RECEIPTS_INVALID", "%s", receiptResult.Reason)
	}
	res.ReceiptCount = len(receipts)
	chain := ledger.VerifyBPlus(receipts, embeddedState)
	if !chain.OK {
		return failBPlus("BPLUS_LEDGER_INVALID", "%s", strings.Join(chain.Findings, "; "))
	}
	petitions, err := parsePetitions(members["petitions.ndjson"])
	if err != nil {
		return failBPlus("PETITIONS_INVALID", "%v", err)
	}
	if binding := ledger.VerifyPetitions(receipts, petitions); !binding.OK {
		return failBPlus("PETITION_BINDING_INVALID", "%s", strings.Join(binding.Findings, "; "))
	}
	receiptSealSigner, receiptSealResult := verifyReceiptSeal(members, receipts, trust)
	if !receiptSealResult.OK {
		return failBPlus("RECEIPT_SEAL_INVALID", "%s", receiptSealResult.Reason)
	}
	if active := embeddedState.Active(); active == nil || bundleSigner != active.OperationalKeyID || receiptSealSigner != active.OperationalKeyID {
		return failBPlus("EXPORT_SIGNER_NOT_ACTIVE", "bundle and receipt-window seals must be signed by the embedded ACTIVE epoch")
	}
	if embeddedAnchor.LedgerBoundary.SequenceNo != len(receipts)-1 || embeddedAnchor.LedgerBoundary.ReceiptID == nil ||
		*embeddedAnchor.LedgerBoundary.ReceiptID != receipts[len(receipts)-1].ReceiptID {
		return failBPlus("EMBEDDED_ANCHOR_BOUNDARY_MISMATCH", "embedded evidence anchor does not bind the bundle's exact receipt head")
	}
	claimedSigners := []string{bundleSigner, receiptSealSigner}
	for _, receipt := range receipts {
		claimedSigners = append(claimedSigners, receipt.SigningKeyID)
	}
	actual, err := canonicalSignerIDs(claimedSigners, trust)
	if err != nil {
		return failBPlus("SIGNING_IDENTITY_INVALID", "%v", err)
	}
	res.SigningKeyIDs = actual
	res.Signature = verdictPass
	res.BundleLedgerIntegrity = verdictPass
	res.EpochAuthorization = verdictPass
	res.EvidenceAnchor = "EMBEDDED_ONLY"
	res.Checks = append(res.Checks, "bundle seal, receipt seal, receipt signatures, chain, petitions, epoch windows, and embedded anchor verified")

	if options.ExpectedIdentityID == "" {
		res.OK = true
		res.IdentityContinuity = verdictIndeterminate
		res.CheckpointSource = "EMBEDDED_ONLY"
		res.CheckpointFreshness = "UNPROVEN_OFFLINE"
		res.SigningKeyStatus = "AUTHENTIC_EMBEDDED_STATUS_ONLY"
		res.OverallTrust = OverallIndeterminate
		res.ReasonCode = "MISSING_EXTERNAL_IDENTITY_PIN"
		res.Reason = "the bundle is internally authentic, but B+ identity continuity requires an independently supplied genesis identity pin"
		return res
	}
	if !identityIDPattern.MatchString(options.ExpectedIdentityID) || options.ExpectedIdentityID != embeddedState.Genesis.IdentityID {
		res.IdentityContinuity = verdictFail
		return notTrustedBPlus(res, "IDENTITY_PIN_MISMATCH", "expected B+ identity %s, bundle carries %s", options.ExpectedIdentityID, embeddedState.Genesis.IdentityID)
	}
	res.IdentityContinuity = verdictPass

	checkpointState, source, checkpointResult := selectCheckpoint(options, embeddedState)
	if !checkpointResult.OK {
		checkpointResult.IdentityID = res.IdentityID
		return checkpointResult
	}
	res.CheckpointSource = source
	res.CheckpointAuthenticity = verdictPass
	res.CheckpointSequence = verdictPass
	res.LifecycleSequence = checkpointState.LastSequence
	res.LifecycleDigest = checkpointState.LastRecordDigest
	if err := verifyCheckpointRequirements(options, checkpointState); err != nil {
		res.CheckpointSequence = verdictFail
		return notTrustedBPlus(res, "MINIMUM_CHECKPOINT_NOT_MET", "%v", err)
	}
	if err := verifyCheckpointReceiptBoundaries(receipts, checkpointState); err != nil {
		res.CheckpointAuthenticity = verdictFail
		return notTrustedBPlus(res, "CHECKPOINT_RECEIPT_BOUNDARY_MISMATCH", "%v", err)
	}
	if err := verifyReceiptAuthorizationAtState(receipts, checkpointState); err != nil {
		res.EpochAuthorization = verdictFail
		return notTrustedBPlus(res, "EPOCH_UNAUTHORIZED", "%v", err)
	}

	externalAnchor, anchorSupplied, anchorErr := loadExternalAnchor(options.ExternalAnchorPath, checkpointState, receipts)
	if anchorErr != nil {
		res.EvidenceAnchor = verdictFail
		return notTrustedBPlus(res, "EXTERNAL_ANCHOR_INVALID", "%v", anchorErr)
	}
	if anchorSupplied {
		res.EvidenceAnchor = "INDEPENDENT_MATCH"
	}
	status, statusIndeterminate := signingStatusForEvidence(receipts, checkpointState, externalAnchor)
	res.SigningKeyStatus = status
	res.CheckpointFreshness = "UNPROVEN_OFFLINE"
	res.Checks = append(res.Checks, fmt.Sprintf("external identity pin and %s lifecycle checkpoint authenticated", strings.ToLower(source)))

	res.OK = true
	if source == "EMBEDDED_ONLY" {
		res.OverallTrust = OverallIndeterminate
		res.ReasonCode = "EMBEDDED_CHECKPOINT_NOT_INDEPENDENT"
		res.Reason = "the identity pin matches, but the only lifecycle status came from inside the bundle"
		return res
	}
	if options.RequireCurrentStatus {
		res.OverallTrust = OverallIndeterminate
		res.ReasonCode = "CURRENT_STATUS_FRESHNESS_UNAVAILABLE"
		res.Reason = "the supplied lifecycle checkpoint is authentic, but an offline verifier cannot prove that no newer revocation exists"
		return res
	}
	if statusIndeterminate {
		res.OverallTrust = OverallIndeterminate
		res.ReasonCode = "EPOCH_TRUST_INDETERMINATE"
		res.Reason = "one or more signatures belong to a suspended or revoked epoch and are not fully covered by an independently retained known-good anchor"
		return res
	}
	res.OverallTrust = OverallVerified
	res.TrustVerdict = OverallVerified
	res.ReasonCode = "BPLUS_VERIFIED_AT_CHECKPOINT"
	res.Reason = "B+ evidence verified at the independently supplied lifecycle checkpoint; current-status freshness was not claimed"
	return res
}

func exactLifecycleTrust(bundleTrust, lifecycleTrust map[string]*keys.Pair) error {
	if len(bundleTrust) != len(lifecycleTrust) {
		return fmt.Errorf("trust_roots.json does not contain exactly the authenticated lifecycle keys")
	}
	for keyID, expected := range lifecycleTrust {
		actual := bundleTrust[keyID]
		if actual == nil || actual.ValidateKeyID(keyID, false) != nil {
			return fmt.Errorf("trust root %s is missing or has another public key", keyID)
		}
		expectedPEM, _ := expected.PublicPEM()
		actualPEM, _ := actual.PublicPEM()
		if string(expectedPEM) != string(actualPEM) {
			return fmt.Errorf("trust root %s differs from lifecycle authority", keyID)
		}
	}
	return nil
}

func selectCheckpoint(options Options, embedded *identity.State) (*identity.State, string, Result) {
	if options.ExternalCheckpointPath != "" && options.TrustStore != "" {
		return nil, "", notTrustedBPlus(newBPlusResult(), "CHECKPOINT_SOURCE_CONFLICT", "choose either an explicit checkpoint file or a retained trust store, not both")
	}
	var checkpoint *identity.LifecycleCheckpoint
	var state *identity.State
	var err error
	source := "EMBEDDED_ONLY"
	if options.ExternalCheckpointPath != "" {
		var raw []byte
		raw, err = readExternalRegular(options.ExternalCheckpointPath, 12*1024*1024)
		if err == nil {
			checkpoint, state, err = identity.ParseLifecycleCheckpoint(raw)
		}
		source = "SUPPLIED_FILE"
	} else if options.TrustStore != "" {
		checkpoint, state, err = identity.LoadStoredCheckpoint(options.TrustStore, options.ExpectedIdentityID)
		source = "RETAINED_STORE"
	} else {
		state = embedded
	}
	if err != nil {
		return nil, source, notTrustedBPlus(newBPlusResult(), "CHECKPOINT_INVALID", "external lifecycle checkpoint: %v", err)
	}
	if source == "EMBEDDED_ONLY" {
		return state, source, Result{OK: true}
	}
	if checkpoint.IdentityID != embedded.Genesis.IdentityID || state.LastSequence < embedded.LastSequence {
		return nil, source, notTrustedBPlus(newBPlusResult(), "CHECKPOINT_ROLLBACK", "external checkpoint is older than or belongs to another identity")
	}
	if len(state.Records) <= embedded.LastSequence || state.Records[embedded.LastSequence].RecordDigest != embedded.LastRecordDigest {
		return nil, source, notTrustedBPlus(newBPlusResult(), "CHECKPOINT_FORK", "external checkpoint is not a descendant of the bundle's authenticated lifecycle")
	}
	return state, source, Result{OK: true}
}

func verifyCheckpointReceiptBoundaries(receipts []*ledger.Receipt, state *identity.State) error {
	for _, record := range state.Records {
		boundary := record.LedgerBoundary
		if boundary.SequenceNo < 0 || boundary.SequenceNo >= len(receipts) {
			continue
		}
		if boundary.ReceiptID == nil || receipts[boundary.SequenceNo].ReceiptID != *boundary.ReceiptID {
			return fmt.Errorf("lifecycle sequence %d does not bind the bundle receipt at sequence %d", record.LifecycleSequence, boundary.SequenceNo)
		}
	}
	return nil
}

func verifyCheckpointRequirements(options Options, state *identity.State) error {
	if options.MinimumCheckpointSequence != nil {
		sequence := *options.MinimumCheckpointSequence
		if sequence < 0 || state.LastSequence < sequence {
			return fmt.Errorf("checkpoint sequence %d is below required minimum %d", state.LastSequence, sequence)
		}
		if options.MinimumCheckpointDigest != "" {
			if sequence >= len(state.Records) || state.Records[sequence].RecordDigest != options.MinimumCheckpointDigest {
				return fmt.Errorf("checkpoint does not contain the required sequence/digest pin")
			}
		}
	} else if options.MinimumCheckpointDigest != "" {
		return fmt.Errorf("a minimum checkpoint digest requires its sequence")
	}
	return nil
}

func verifyReceiptAuthorizationAtState(receipts []*ledger.Receipt, state *identity.State) error {
	epochByKey := map[string]*identity.EpochState{}
	for _, epoch := range state.Epochs {
		epochByKey[epoch.OperationalKeyID] = epoch
	}
	for _, receipt := range receipts {
		epoch := epochByKey[receipt.SigningKeyID]
		if epoch == nil {
			return fmt.Errorf("receipt %d names no authenticated lifecycle epoch", receipt.SequenceNo)
		}
		authorized := false
		for _, window := range epoch.Windows {
			if receipt.SequenceNo > window.StartAfter.SequenceNo && (window.EndAt == nil || receipt.SequenceNo <= window.EndAt.SequenceNo) {
				authorized = true
				break
			}
		}
		if !authorized {
			return fmt.Errorf("receipt %d is outside epoch %d's authorization windows", receipt.SequenceNo, epoch.EpochNumber)
		}
	}
	return nil
}

func loadExternalAnchor(path string, state *identity.State, receipts []*ledger.Receipt) (*identity.EvidenceAnchor, bool, error) {
	if path == "" {
		return nil, false, nil
	}
	raw, err := readExternalRegular(path, 1024*1024)
	if err != nil {
		return nil, true, err
	}
	anchor, err := identity.ParseEvidenceAnchor(raw)
	if err != nil {
		return nil, true, err
	}
	if err := identity.ValidateEvidenceAnchor(anchor, state); err != nil {
		return nil, true, err
	}
	sequence := anchor.LedgerBoundary.SequenceNo
	if sequence < 0 || sequence >= len(receipts) || anchor.LedgerBoundary.ReceiptID == nil || receipts[sequence].ReceiptID != *anchor.LedgerBoundary.ReceiptID {
		return nil, true, fmt.Errorf("external anchor does not match an exact receipt in this bundle")
	}
	return anchor, true, nil
}

func signingStatusForEvidence(receipts []*ledger.Receipt, state *identity.State, anchor *identity.EvidenceAnchor) (string, bool) {
	used := map[string]int{}
	for _, receipt := range receipts {
		current, exists := used[receipt.SigningKeyID]
		if !exists || receipt.SequenceNo > current {
			used[receipt.SigningKeyID] = receipt.SequenceNo
		}
	}
	statuses := map[string]bool{}
	indeterminate := false
	for _, epoch := range state.Epochs {
		maxSequence, present := used[epoch.OperationalKeyID]
		if !present {
			continue
		}
		statuses[epoch.Status] = true
		if epoch.Status == identity.StatusSuspended || epoch.Status == identity.StatusRevoked {
			covered := anchor != nil && epoch.KnownGoodAnchor != nil && *epoch.KnownGoodAnchor == anchor.AnchorDigest &&
				anchor.EpochNumber == epoch.EpochNumber && anchor.LedgerBoundary.SequenceNo >= maxSequence
			if !covered {
				indeterminate = true
			}
		}
	}
	names := make([]string, 0, len(statuses))
	for status := range statuses {
		names = append(names, status)
	}
	sort.Strings(names)
	if indeterminate {
		return "INDETERMINATE_" + strings.Join(names, "+"), true
	}
	if anchor != nil {
		return "AUTHORIZED_AT_INDEPENDENT_ANCHOR_" + strings.Join(names, "+"), false
	}
	return "AUTHORIZED_" + strings.Join(names, "+"), false
}

func readExternalRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("external trust input is not a regular file")
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("external trust input exceeds %d bytes", maximum)
	}
	return os.ReadFile(path)
}
