package identity

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
)

// NewGenesis creates and signs the stable identity authority and its first
// lifecycle record. The recovery private key is used only in memory.
func NewGenesis(root, epochZero *keys.Pair, label, action string, boundary LedgerBoundary) (*Genesis, *LifecycleRecord, error) {
	if action != ActionGenesis && action != ActionMigration {
		return nil, nil, fmt.Errorf("identity: genesis action must be GENESIS or MIGRATION")
	}
	if err := validateBoundary(boundary); err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	recoveryID, err := root.KeyID()
	if err != nil {
		return nil, nil, err
	}
	recoveryPEM, err := root.PublicPEM()
	if err != nil {
		return nil, nil, err
	}
	epochID, err := epochZero.KeyID()
	if err != nil {
		return nil, nil, err
	}
	epochPEM, err := epochZero.PublicPEM()
	if err != nil {
		return nil, nil, err
	}
	g := &Genesis{
		Schema: GenesisSchema, ProtocolVersion: ProtocolVersion,
		IdentityNonceB64:  base64.StdEncoding.EncodeToString(nonce),
		RecoveryRootKeyID: recoveryID, RecoveryRootPublicKeyPEM: string(recoveryPEM),
		EpochZeroKeyID: epochID, EpochZeroPublicKeyPEM: string(epochPEM),
		Canonicalization: "RFC8785-JCS", AdvisoryLabel: strings.TrimSpace(label),
		GenesisPolicy: GenesisPolicy{
			OneActiveOperationalKey: true,
			ConcurrentSigning:       false,
			RecoveryRootRotation:    false,
		},
	}
	g.IdentityID, err = computeIdentityID(g)
	if err != nil {
		return nil, nil, err
	}
	g.RecoverySignatureB64, err = signDomain(root, genesisDomain, genesisSigned(g))
	if err != nil {
		return nil, nil, err
	}
	g.EpochZeroProofB64, err = signDomain(epochZero, genesisDomain, genesisSigned(g))
	if err != nil {
		return nil, nil, err
	}
	record := &LifecycleRecord{
		Schema: LifecycleSchema, ProtocolVersion: ProtocolVersion,
		IdentityID: g.IdentityID, LifecycleSequence: 0,
		PreviousRecordDigest: nil, Action: action,
		EpochNumber: 0, OperationalKeyID: epochID,
		OperationalPublicKeyPEM: string(epochPEM), OperationalStatus: StatusActive,
		LedgerBoundary: boundary, PreviousEpoch: nil, EvidenceAnchorDigest: nil,
		ReasonCode: map[bool]string{true: "LEGACY_IDENTITY_ENROLLED", false: "IDENTITY_INITIALIZED"}[action == ActionMigration],
	}
	if err := signRecord(record, root, nil, epochZero); err != nil {
		return nil, nil, err
	}
	return g, record, nil
}

// NewLifecycleRecord constructs and signs the next lawful lifecycle record.
// newOperational is required for ROTATE and RECOVER; currentOperational is
// required when the current epoch must prove possession.
func NewLifecycleRecord(state *State, root, currentOperational, newOperational *keys.Pair, request MutationRequest) (*LifecycleRecord, error) {
	if state == nil || state.Genesis == nil || state.LastSequence < 0 {
		return nil, fmt.Errorf("identity: validated lifecycle state is required")
	}
	if root == nil || root.ValidateKeyID(state.Genesis.RecoveryRootKeyID, false) != nil {
		return nil, fmt.Errorf("identity: recovery package does not control this identity")
	}
	if err := validateBoundary(request.Boundary); err != nil {
		return nil, err
	}
	if err := validateReason(request.ReasonCode); err != nil {
		return nil, err
	}
	previousDigest := state.LastRecordDigest
	record := &LifecycleRecord{
		Schema: LifecycleSchema, ProtocolVersion: ProtocolVersion,
		IdentityID: state.Genesis.IdentityID, LifecycleSequence: state.LastSequence + 1,
		PreviousRecordDigest: &previousDigest, Action: request.Action,
		LedgerBoundary: request.Boundary, EvidenceAnchorDigest: copyString(request.EvidenceAnchorDigest),
		ReasonCode: request.ReasonCode,
	}
	latest := state.Epochs[latestEpochNumber(state)]
	var subject *keys.Pair
	var retiring *keys.Pair
	switch request.Action {
	case ActionRotate:
		active := state.Active()
		if active == nil || currentOperational == nil || currentOperational.ValidateKeyID(active.OperationalKeyID, false) != nil {
			return nil, fmt.Errorf("identity: routine rotation requires the active operational key")
		}
		if newOperational == nil {
			return nil, fmt.Errorf("identity: routine rotation requires a new operational key")
		}
		record.PreviousEpoch = &PreviousEpoch{
			EpochNumber: active.EpochNumber, OperationalKeyID: active.OperationalKeyID,
			OperationalStatus: StatusRetired, FinalLedgerBoundary: request.Boundary,
		}
		record.EpochNumber = active.EpochNumber + 1
		record.OperationalStatus = StatusActive
		subject = newOperational
		retiring = currentOperational
	case ActionRecover:
		if newOperational == nil {
			return nil, fmt.Errorf("identity: lost-key recovery requires a new operational key")
		}
		record.PreviousEpoch = &PreviousEpoch{
			EpochNumber: latest.EpochNumber, OperationalKeyID: latest.OperationalKeyID,
			OperationalStatus: StatusRevoked, FinalLedgerBoundary: request.Boundary,
		}
		record.EpochNumber = latest.EpochNumber + 1
		record.OperationalStatus = StatusActive
		subject = newOperational
	case ActionSuspend:
		active := state.Active()
		if active == nil || currentOperational == nil || currentOperational.ValidateKeyID(active.OperationalKeyID, false) != nil {
			return nil, fmt.Errorf("identity: suspension requires the active operational key")
		}
		record.EpochNumber = active.EpochNumber
		record.OperationalStatus = StatusSuspended
		subject = currentOperational
		retiring = currentOperational
	case ActionResume:
		if state.Active() != nil || latest.Status != StatusSuspended || currentOperational == nil ||
			currentOperational.ValidateKeyID(latest.OperationalKeyID, false) != nil {
			return nil, fmt.Errorf("identity: resumption requires possession of the latest suspended operational key")
		}
		record.EpochNumber = latest.EpochNumber
		record.OperationalStatus = StatusActive
		subject = currentOperational
	case ActionRevoke:
		if latest.Status == StatusRetired || latest.Status == StatusRevoked {
			return nil, fmt.Errorf("identity: latest operational epoch is already final")
		}
		record.EpochNumber = latest.EpochNumber
		record.OperationalStatus = StatusRevoked
		subject = state.Trust[latest.OperationalKeyID]
	default:
		return nil, fmt.Errorf("identity: unsupported lifecycle action %q", request.Action)
	}
	if subject == nil {
		return nil, fmt.Errorf("identity: operational public key is unavailable")
	}
	keyID, err := subject.KeyID()
	if err != nil {
		return nil, err
	}
	publicPEM, err := subject.PublicPEM()
	if err != nil {
		return nil, err
	}
	record.OperationalKeyID = keyID
	record.OperationalPublicKeyPEM = string(publicPEM)
	proofPair := subject
	if request.Action == ActionRevoke {
		proofPair = nil
	}
	if err := signRecord(record, root, retiring, proofPair); err != nil {
		return nil, err
	}
	return record, nil
}

func validateGenesis(g *Genesis) (*keys.Pair, *keys.Pair, error) {
	if g == nil || g.Schema != GenesisSchema || g.ProtocolVersion != ProtocolVersion ||
		g.Canonicalization != "RFC8785-JCS" || !g.GenesisPolicy.OneActiveOperationalKey ||
		g.GenesisPolicy.ConcurrentSigning || g.GenesisPolicy.RecoveryRootRotation ||
		!identityIDPattern.MatchString(g.IdentityID) || !keyIDPattern.MatchString(g.RecoveryRootKeyID) ||
		!keyIDPattern.MatchString(g.EpochZeroKeyID) || len(g.AdvisoryLabel) > 200 {
		return nil, nil, fmt.Errorf("identity: genesis policy or required fields are invalid")
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(g.IdentityNonceB64)
	if err != nil || len(nonce) != 32 {
		return nil, nil, fmt.Errorf("identity: genesis nonce must be 32 random bytes")
	}
	recovery, err := keys.LoadPublicPEMText(g.RecoveryRootPublicKeyPEM)
	if err != nil || recovery.ValidateKeyID(g.RecoveryRootKeyID, false) != nil {
		return nil, nil, fmt.Errorf("identity: genesis recovery root is invalid")
	}
	epochZero, err := keys.LoadPublicPEMText(g.EpochZeroPublicKeyPEM)
	if err != nil || epochZero.ValidateKeyID(g.EpochZeroKeyID, false) != nil {
		return nil, nil, fmt.Errorf("identity: genesis epoch-zero key is invalid")
	}
	expectedID, err := computeIdentityID(g)
	if err != nil || expectedID != g.IdentityID {
		return nil, nil, fmt.Errorf("identity: genesis digest does not match identity_id")
	}
	if validateSignatureEncoding(g.RecoverySignatureB64) != nil || !verifyDomain(recovery, genesisDomain, genesisSigned(g), g.RecoverySignatureB64) {
		return nil, nil, fmt.Errorf("identity: genesis recovery signature is invalid")
	}
	if validateSignatureEncoding(g.EpochZeroProofB64) != nil || !verifyDomain(epochZero, genesisDomain, genesisSigned(g), g.EpochZeroProofB64) {
		return nil, nil, fmt.Errorf("identity: genesis epoch-zero proof is invalid")
	}
	return recovery, epochZero, nil
}

func signRecord(record *LifecycleRecord, root, retiring, operational *keys.Pair) error {
	digest, err := computeRecordDigest(record)
	if err != nil {
		return err
	}
	record.RecordDigest = digest
	record.RecoverySignatureB64, err = signDomain(root, recordDomain, recordSigned(record))
	if err != nil {
		return err
	}
	needsRetiring := record.Action == ActionRotate || record.Action == ActionSuspend
	needsProof := record.Action == ActionGenesis || record.Action == ActionMigration || record.Action == ActionRotate ||
		record.Action == ActionRecover || record.Action == ActionResume
	if needsRetiring {
		if retiring == nil {
			return fmt.Errorf("identity: retiring operational signature is required")
		}
		signature, signErr := signDomain(retiring, recordDomain, recordSigned(record))
		if signErr != nil {
			return signErr
		}
		record.RetiringSignatureB64 = &signature
	}
	if needsProof {
		if operational == nil {
			return fmt.Errorf("identity: operational proof of possession is required")
		}
		signature, signErr := signDomain(operational, recordDomain, recordSigned(record))
		if signErr != nil {
			return signErr
		}
		record.OperationalProofB64 = &signature
	}
	return nil
}

func validateRecordBasics(record *LifecycleRecord, recovery, operational, retiring *keys.Pair) error {
	if record == nil || record.Schema != LifecycleSchema || record.ProtocolVersion != ProtocolVersion ||
		!identityIDPattern.MatchString(record.IdentityID) || record.LifecycleSequence < 0 || record.EpochNumber < 0 ||
		!keyIDPattern.MatchString(record.OperationalKeyID) || !hex64Pattern.MatchString(record.RecordDigest) {
		return fmt.Errorf("identity: lifecycle record has invalid required fields")
	}
	if err := validateBoundary(record.LedgerBoundary); err != nil {
		return fmt.Errorf("identity: lifecycle record: %w", err)
	}
	if err := validateReason(record.ReasonCode); err != nil {
		return fmt.Errorf("identity: lifecycle record: %w", err)
	}
	if record.EvidenceAnchorDigest != nil && !hex64Pattern.MatchString(*record.EvidenceAnchorDigest) {
		return fmt.Errorf("identity: evidence anchor digest must be 64 lowercase hex characters")
	}
	if operational == nil || operational.ValidateKeyID(record.OperationalKeyID, false) != nil {
		return fmt.Errorf("identity: lifecycle operational key does not match its fingerprint")
	}
	expectedDigest, err := computeRecordDigest(record)
	if err != nil || expectedDigest != record.RecordDigest {
		return fmt.Errorf("identity: lifecycle record digest does not match its contents")
	}
	if validateSignatureEncoding(record.RecoverySignatureB64) != nil || !verifyDomain(recovery, recordDomain, recordSigned(record), record.RecoverySignatureB64) {
		return fmt.Errorf("identity: lifecycle recovery-root signature is invalid")
	}
	needsRetiring := record.Action == ActionRotate || record.Action == ActionSuspend
	needsProof := record.Action == ActionGenesis || record.Action == ActionMigration || record.Action == ActionRotate ||
		record.Action == ActionRecover || record.Action == ActionResume
	if needsRetiring {
		if retiring == nil || record.RetiringSignatureB64 == nil || validateSignatureEncoding(*record.RetiringSignatureB64) != nil ||
			!verifyDomain(retiring, recordDomain, recordSigned(record), *record.RetiringSignatureB64) {
			return fmt.Errorf("identity: lifecycle retiring-key signature is invalid")
		}
	} else if record.RetiringSignatureB64 != nil {
		return fmt.Errorf("identity: lifecycle record has an unauthorized retiring-key signature")
	}
	if needsProof {
		if record.OperationalProofB64 == nil || validateSignatureEncoding(*record.OperationalProofB64) != nil ||
			!verifyDomain(operational, recordDomain, recordSigned(record), *record.OperationalProofB64) {
			return fmt.Errorf("identity: lifecycle operational proof is invalid")
		}
	} else if record.OperationalProofB64 != nil {
		return fmt.Errorf("identity: lifecycle record has an unauthorized operational proof")
	}
	return nil
}

// DeriveState validates the complete lifecycle chain and computes epoch
// authorization windows without reading any private key.
func DeriveState(home string, genesis *Genesis, records []*LifecycleRecord) (*State, error) {
	recovery, epochZero, err := validateGenesis(genesis)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 || len(records) > 10000 {
		return nil, fmt.Errorf("identity: lifecycle must contain 1 to 10000 records")
	}
	state := &State{
		Home: home, Genesis: genesis, Records: records,
		Epochs: map[int]*EpochState{}, Trust: map[string]*keys.Pair{},
		RecoveryPublic: recovery, LastSequence: -1,
	}
	var active *EpochState
	var previousDigest *string
	for index, record := range records {
		if record.LifecycleSequence != index || record.IdentityID != genesis.IdentityID {
			return nil, fmt.Errorf("identity: lifecycle sequence %d is missing, duplicated, or names another identity", index)
		}
		if !sameOptional(record.PreviousRecordDigest, previousDigest) {
			return nil, fmt.Errorf("identity: lifecycle sequence %d breaks the previous-record chain", index)
		}
		if index > 0 {
			priorBoundary := records[index-1].LedgerBoundary
			if record.LedgerBoundary.SequenceNo < priorBoundary.SequenceNo ||
				(record.LedgerBoundary.SequenceNo == priorBoundary.SequenceNo && !equalBoundary(record.LedgerBoundary, priorBoundary)) {
				return nil, fmt.Errorf("identity: lifecycle sequence %d moves the ledger boundary backward or conflicts at the same sequence", index)
			}
		}
		operational, loadErr := keys.LoadPublicPEMText(record.OperationalPublicKeyPEM)
		if loadErr != nil {
			return nil, fmt.Errorf("identity: lifecycle sequence %d public key: %w", index, loadErr)
		}
		var retiring *keys.Pair
		if record.PreviousEpoch != nil {
			prior := state.Epochs[record.PreviousEpoch.EpochNumber]
			if prior != nil {
				retiring = state.Trust[prior.OperationalKeyID]
			}
		} else if active != nil {
			retiring = state.Trust[active.OperationalKeyID]
		}
		if err := validateRecordBasics(record, recovery, operational, retiring); err != nil {
			return nil, fmt.Errorf("identity: lifecycle sequence %d: %w", index, err)
		}
		if index == 0 {
			if (record.Action != ActionGenesis && record.Action != ActionMigration) || record.PreviousRecordDigest != nil ||
				record.EpochNumber != 0 || record.OperationalKeyID != genesis.EpochZeroKeyID || record.OperationalStatus != StatusActive ||
				record.PreviousEpoch != nil || record.EvidenceAnchorDigest != nil {
				return nil, fmt.Errorf("identity: lifecycle genesis record is inconsistent")
			}
			if record.Action == ActionGenesis && record.LedgerBoundary.SequenceNo != -1 {
				return nil, fmt.Errorf("identity: a new identity must begin at an empty ledger")
			}
			state.Trust[record.OperationalKeyID] = epochZero
			epoch := &EpochState{
				EpochNumber: 0, OperationalKeyID: record.OperationalKeyID,
				OperationalPublicPEM: record.OperationalPublicKeyPEM, Status: StatusActive,
				Windows: []AuthorizationWindow{{StartAfter: LedgerBoundary{SequenceNo: -1}}},
			}
			state.Epochs[0] = epoch
			active = epoch
			zero := 0
			state.ActiveEpoch = &zero
		} else if err := applyLifecycleRecord(state, &active, record, operational); err != nil {
			return nil, fmt.Errorf("identity: lifecycle sequence %d: %w", index, err)
		}
		digest := record.RecordDigest
		previousDigest = &digest
		state.LastSequence = index
		state.LastRecordDigest = digest
	}
	return state, nil
}

func applyLifecycleRecord(state *State, active **EpochState, record *LifecycleRecord, operational *keys.Pair) error {
	latestNumber := latestEpochNumber(state)
	switch record.Action {
	case ActionRotate, ActionRecover:
		if record.PreviousEpoch == nil || record.EpochNumber != latestNumber+1 || record.OperationalStatus != StatusActive {
			return fmt.Errorf("transition must close the latest epoch and activate exactly its successor")
		}
		prior := state.Epochs[record.PreviousEpoch.EpochNumber]
		if prior == nil || prior.OperationalKeyID != record.PreviousEpoch.OperationalKeyID ||
			prior.EpochNumber != latestNumber || !equalBoundary(record.PreviousEpoch.FinalLedgerBoundary, record.LedgerBoundary) {
			return fmt.Errorf("transition does not bind the exact previous epoch and ledger boundary")
		}
		if record.Action == ActionRotate {
			if *active != prior || prior.Status != StatusActive || record.PreviousEpoch.OperationalStatus != StatusRetired {
				return fmt.Errorf("routine rotation requires the currently active epoch and retires it")
			}
		} else {
			if *active != nil && *active != prior {
				return fmt.Errorf("recovery names an epoch that is not current")
			}
			if record.PreviousEpoch.OperationalStatus != StatusRevoked {
				return fmt.Errorf("lost-key recovery must permanently revoke the previous epoch")
			}
		}
		closeEpoch(prior, record.PreviousEpoch.OperationalStatus, record.LedgerBoundary, record.EvidenceAnchorDigest)
		if _, exists := state.Trust[record.OperationalKeyID]; exists || record.OperationalKeyID == prior.OperationalKeyID {
			return fmt.Errorf("new epoch must use a previously unseen operational key")
		}
		state.Trust[record.OperationalKeyID] = operational
		next := &EpochState{
			EpochNumber: record.EpochNumber, OperationalKeyID: record.OperationalKeyID,
			OperationalPublicPEM: record.OperationalPublicKeyPEM, Status: StatusActive,
			Windows: []AuthorizationWindow{{StartAfter: record.LedgerBoundary}},
		}
		state.Epochs[next.EpochNumber] = next
		*active = next
		number := next.EpochNumber
		state.ActiveEpoch = &number
	case ActionSuspend:
		if *active == nil || record.EpochNumber != (*active).EpochNumber || record.OperationalKeyID != (*active).OperationalKeyID ||
			record.OperationalStatus != StatusSuspended || record.PreviousEpoch != nil {
			return fmt.Errorf("suspension must close the current active epoch")
		}
		closeEpoch(*active, StatusSuspended, record.LedgerBoundary, record.EvidenceAnchorDigest)
		*active = nil
		state.ActiveEpoch = nil
	case ActionResume:
		epoch := state.Epochs[record.EpochNumber]
		if *active != nil || epoch == nil || record.EpochNumber != latestNumber || epoch.Status != StatusSuspended ||
			record.OperationalKeyID != epoch.OperationalKeyID || record.OperationalStatus != StatusActive || record.PreviousEpoch != nil {
			return fmt.Errorf("resumption requires the latest suspended epoch")
		}
		epoch.Status = StatusActive
		epoch.Windows = append(epoch.Windows, AuthorizationWindow{StartAfter: record.LedgerBoundary})
		*active = epoch
		number := epoch.EpochNumber
		state.ActiveEpoch = &number
	case ActionRevoke:
		epoch := state.Epochs[record.EpochNumber]
		if epoch == nil || record.EpochNumber != latestNumber || record.OperationalKeyID != epoch.OperationalKeyID ||
			record.OperationalStatus != StatusRevoked || record.PreviousEpoch != nil || epoch.Status == StatusRevoked || epoch.Status == StatusRetired {
			return fmt.Errorf("revocation must permanently close the latest non-retired epoch")
		}
		if *active == epoch {
			closeEpoch(epoch, StatusRevoked, record.LedgerBoundary, record.EvidenceAnchorDigest)
			*active = nil
			state.ActiveEpoch = nil
		} else {
			epoch.Status = StatusRevoked
			epoch.KnownGoodAnchor = copyString(record.EvidenceAnchorDigest)
		}
	default:
		return fmt.Errorf("unknown lifecycle action %q", record.Action)
	}
	return nil
}

func closeEpoch(epoch *EpochState, status string, boundary LedgerBoundary, anchor *string) {
	if len(epoch.Windows) > 0 && epoch.Windows[len(epoch.Windows)-1].EndAt == nil {
		copyBoundary := boundary
		epoch.Windows[len(epoch.Windows)-1].EndAt = &copyBoundary
	}
	epoch.Status = status
	epoch.KnownGoodAnchor = copyString(anchor)
}

func latestEpochNumber(state *State) int {
	numbers := make([]int, 0, len(state.Epochs))
	for number := range state.Epochs {
		numbers = append(numbers, number)
	}
	sort.Ints(numbers)
	return numbers[len(numbers)-1]
}

func sameOptional(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func equalBoundary(left, right LedgerBoundary) bool {
	return left.SequenceNo == right.SequenceNo && sameOptional(left.ReceiptID, right.ReceiptID)
}

func copyString(value *string) *string {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}
