package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/identity"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

const bPlusManifestVersion = "bplus-v1"

func buildBPlus(l *ledger.Ledger, outputPath string) error {
	if l.IdentityState == nil || l.IdentityState.Active() == nil || l.IdentityState.ActivePair == nil {
		return invalidEvidenceError("B+ export requires one ACTIVE operational signing epoch")
	}
	receiptBytes, err := os.ReadFile(l.ReceiptsPath)
	if err != nil {
		return invalidEvidenceError("cannot read receipts: %v", err)
	}
	receipts, parsed := parseReceipts(map[string][]byte{"receipts.ndjson": receiptBytes})
	if !parsed.OK {
		return invalidEvidenceError("%s", parsed.Reason)
	}
	if res := ledger.VerifyBPlus(receipts, l.IdentityState); !res.OK {
		return invalidEvidenceError("B+ receipt authorization failed: %s", strings.Join(res.Findings, "; "))
	}
	petitionBytes, err := os.ReadFile(l.PetitionsPath)
	if err != nil {
		return invalidEvidenceError("cannot read stored requests: %v", err)
	}
	petitions, err := parsePetitions(petitionBytes)
	if err != nil {
		return invalidEvidenceError("stored requests are malformed: %v", err)
	}
	if res := ledger.VerifyPetitions(receipts, petitions); !res.OK {
		return invalidEvidenceError("stored request verification failed: %s", strings.Join(res.Findings, "; "))
	}

	state := l.IdentityState
	card, err := identity.NewIdentityCard(state)
	if err != nil {
		return invalidEvidenceError("create identity card: %v", err)
	}
	checkpoint, err := identity.NewLifecycleCheckpoint(state)
	if err != nil {
		return invalidEvidenceError("create lifecycle checkpoint: %v", err)
	}
	anchor, err := identity.NewEvidenceAnchor(state, l.Boundary(), state.ActivePair)
	if err != nil {
		return invalidEvidenceError("create evidence anchor: %v", err)
	}
	genesisBytes, err := os.ReadFile(filepath.Join(l.Home, "identity", "genesis.json"))
	if err != nil {
		return invalidEvidenceError("read identity genesis: %v", err)
	}
	lifecycleBytes, err := os.ReadFile(filepath.Join(l.Home, "identity", "lifecycle.ndjson"))
	if err != nil {
		return invalidEvidenceError("read lifecycle chain: %v", err)
	}

	members := map[string][]byte{
		"receipts.ndjson":           receiptBytes,
		"petitions.ndjson":          petitionBytes,
		"revocations.json":          []byte("[]\n"),
		"identity/genesis.json":     genesisBytes,
		"identity/lifecycle.ndjson": lifecycleBytes,
	}
	for name, value := range map[string]any{
		"identity/card.json":            card,
		"identity/checkpoint.json":      checkpoint,
		"identity/evidence_anchor.json": anchor,
	} {
		raw, marshalErr := json.MarshalIndent(value, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		members[name] = append(raw, '\n')
	}

	trustKeys := map[string]string{}
	keyIDs := make([]string, 0, len(state.Trust))
	for keyID := range state.Trust {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	for _, keyID := range keyIDs {
		pemBytes, encodeErr := state.Trust[keyID].PublicPEM()
		if encodeErr != nil {
			return invalidEvidenceError("encode lifecycle trust key %s: %v", keyID, encodeErr)
		}
		trustKeys[keyID] = string(pemBytes)
	}
	trustRoots, err := json.MarshalIndent(map[string]any{"ed25519_public_keys": trustKeys}, "", "  ")
	if err != nil {
		return err
	}
	members["trust_roots.json"] = trustRoots

	seal, err := receiptSeal(receipts, l.KeyID, state.ActivePair)
	if err != nil {
		return err
	}
	sealsJSON, err := json.MarshalIndent([]any{seal}, "", "  ")
	if err != nil {
		return err
	}
	members["seals.json"] = append(sealsJSON, '\n')

	fileHashes := map[string]any{}
	for name, data := range members {
		fileHashes[name] = canon.SHA256Hex(data)
	}
	manifest, err := json.MarshalIndent(map[string]any{
		"created_at": nowISO(), "files": fileHashes, "version": bPlusManifestVersion,
		"identity_id":            state.Genesis.IdentityID,
		"checkpoint_sequence":    state.LastSequence,
		"checkpoint_digest":      state.LastRecordDigest,
		"evidence_anchor_digest": anchor.AnchorDigest,
	}, "", "  ")
	if err != nil {
		return err
	}
	members["MANIFEST.json"] = manifest
	bundleSeal, err := bundleSealBytes(members, l.KeyID, state.ActivePair)
	if err != nil {
		return err
	}
	members["BUNDLE_SEAL.json"] = bundleSeal
	if err := validateMemberLimits(members); err != nil {
		return err
	}
	return writeTarGzAtomic(outputPath, members)
}

func parseBPlusAuthority(members map[string][]byte) (*identity.State, *identity.EvidenceAnchor, Result) {
	card, err := identity.ParseIdentityCard(members["identity/card.json"])
	if err != nil {
		return nil, nil, failBPlus("IDENTITY_CARD_INVALID", "identity card: %v", err)
	}
	checkpoint, checkpointState, err := identity.ParseLifecycleCheckpoint(members["identity/checkpoint.json"])
	if err != nil {
		return nil, nil, failBPlus("CHECKPOINT_INVALID", "embedded lifecycle checkpoint: %v", err)
	}
	var genesis identity.Genesis
	if err := strictjson.UnmarshalExact(members["identity/genesis.json"], &genesis); err != nil {
		return nil, nil, failBPlus("GENESIS_INVALID", "identity genesis: %v", err)
	}
	records, err := identity.ParseLifecycleNDJSON(members["identity/lifecycle.ndjson"])
	if err != nil {
		return nil, nil, failBPlus("LIFECYCLE_INVALID", "%v", err)
	}
	standaloneState, err := identity.DeriveState("", &genesis, records)
	if err != nil {
		return nil, nil, failBPlus("LIFECYCLE_INVALID", "%v", err)
	}
	if !reflect.DeepEqual(card.Genesis, &genesis) || card.IdentityID != checkpoint.IdentityID ||
		!reflect.DeepEqual(checkpoint.Genesis, &genesis) || !reflect.DeepEqual(checkpoint.LifecycleRecords, records) ||
		checkpointState.LastRecordDigest != standaloneState.LastRecordDigest {
		return nil, nil, failBPlus("AUTHORITY_SUBSTITUTION", "B+ identity authority members do not describe one identical genesis and lifecycle")
	}
	anchor, err := identity.ParseEvidenceAnchor(members["identity/evidence_anchor.json"])
	if err != nil {
		return nil, nil, failBPlus("EVIDENCE_ANCHOR_INVALID", "embedded evidence anchor: %v", err)
	}
	if err := identity.ValidateEvidenceAnchor(anchor, standaloneState); err != nil {
		return nil, nil, failBPlus("EVIDENCE_ANCHOR_INVALID", "%v", err)
	}
	return standaloneState, anchor, Result{OK: true}
}
