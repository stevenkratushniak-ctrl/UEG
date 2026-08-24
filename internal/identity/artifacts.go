package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stevenkratushniak-ctrl/ueg/internal/filelock"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

// NewIdentityCard returns the immutable public identity genesis.
func NewIdentityCard(state *State) (*IdentityCard, error) {
	if state == nil || state.Genesis == nil {
		return nil, fmt.Errorf("identity: validated identity state is required")
	}
	return &IdentityCard{
		Schema: CardSchema, ProtocolVersion: ProtocolVersion,
		IdentityID: state.Genesis.IdentityID, AdvisoryLabel: state.Genesis.AdvisoryLabel,
		Genesis: state.Genesis,
	}, nil
}

// NewLifecycleCheckpoint returns the complete authenticated lifecycle known to
// this home. It contains public material only.
func NewLifecycleCheckpoint(state *State) (*LifecycleCheckpoint, error) {
	if state == nil || state.Genesis == nil || state.LastSequence < 0 {
		return nil, fmt.Errorf("identity: validated lifecycle state is required")
	}
	return &LifecycleCheckpoint{
		Schema: CheckpointSchema, ProtocolVersion: ProtocolVersion,
		IdentityID: state.Genesis.IdentityID, Genesis: state.Genesis,
		LifecycleRecords: state.Records, CheckpointSequence: state.LastSequence,
		CheckpointDigest: state.LastRecordDigest,
	}, nil
}

// NewEvidenceAnchor signs an exact ledger head with the currently ACTIVE
// operational key. It does not claim trusted time.
func NewEvidenceAnchor(state *State, boundary LedgerBoundary, pair *keys.Pair) (*EvidenceAnchor, error) {
	if err := validateBoundary(boundary); err != nil {
		return nil, err
	}
	active := state.Active()
	if active == nil || active.Status != StatusActive || pair == nil || pair.ValidateKeyID(active.OperationalKeyID, false) != nil {
		return nil, fmt.Errorf("identity: an ACTIVE operational key is required to create an evidence anchor")
	}
	anchor := &EvidenceAnchor{
		Schema: AnchorSchema, ProtocolVersion: ProtocolVersion,
		IdentityID: state.Genesis.IdentityID, EpochNumber: active.EpochNumber,
		OperationalKeyID: active.OperationalKeyID, LedgerBoundary: boundary,
		LifecycleSequence: state.LastSequence, LifecycleRecordDigest: state.LastRecordDigest,
	}
	digest, err := computeAnchorDigest(anchor)
	if err != nil {
		return nil, err
	}
	anchor.AnchorDigest = digest
	anchor.SignatureB64, err = signDomain(pair, anchorDomain, anchorSigned(anchor))
	if err != nil {
		return nil, err
	}
	return anchor, nil
}

// ValidateEvidenceAnchor validates structure, lifecycle binding, and the
// operational signature. Independent retention is a verifier input, not a
// property an anchor can assert about itself.
func ValidateEvidenceAnchor(anchor *EvidenceAnchor, state *State) error {
	if anchor == nil || state == nil || anchor.Schema != AnchorSchema || anchor.ProtocolVersion != ProtocolVersion ||
		anchor.IdentityID != state.Genesis.IdentityID || anchor.EpochNumber < 0 || !keyIDPattern.MatchString(anchor.OperationalKeyID) ||
		anchor.LifecycleSequence < 0 || !hex64Pattern.MatchString(anchor.LifecycleRecordDigest) ||
		!hex64Pattern.MatchString(anchor.AnchorDigest) {
		return fmt.Errorf("identity: evidence anchor required fields are invalid")
	}
	if err := validateBoundary(anchor.LedgerBoundary); err != nil {
		return fmt.Errorf("identity: evidence anchor: %w", err)
	}
	if anchor.LifecycleSequence >= len(state.Records) || state.Records[anchor.LifecycleSequence].RecordDigest != anchor.LifecycleRecordDigest {
		return fmt.Errorf("identity: evidence anchor lifecycle checkpoint is not in the supplied chain")
	}
	epoch := state.Epochs[anchor.EpochNumber]
	if epoch == nil || epoch.OperationalKeyID != anchor.OperationalKeyID {
		return fmt.Errorf("identity: evidence anchor names an unknown operational epoch")
	}
	expected, err := computeAnchorDigest(anchor)
	if err != nil || expected != anchor.AnchorDigest {
		return fmt.Errorf("identity: evidence anchor digest does not match its contents")
	}
	pair := state.Trust[anchor.OperationalKeyID]
	if validateSignatureEncoding(anchor.SignatureB64) != nil || !verifyDomain(pair, anchorDomain, anchorSigned(anchor), anchor.SignatureB64) {
		return fmt.Errorf("identity: evidence anchor signature is invalid")
	}
	return nil
}

// WritePublicArtifact writes and verifies a public identity artifact without
// replacing an existing destination.
func WritePublicArtifact(destination string, value any, verify func([]byte) error) error {
	destination, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent := filepath.Dir(destination)
	if info, statErr := os.Stat(parent); statErr != nil || !info.IsDir() {
		return fmt.Errorf("identity: artifact destination parent is not an existing directory: %s", parent)
	}
	if _, statErr := os.Lstat(destination); statErr == nil {
		return fmt.Errorf("identity: artifact destination already exists: %s", destination)
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if verify != nil {
		if err := verify(data); err != nil {
			return fmt.Errorf("identity: artifact self-verification failed: %w", err)
		}
	}
	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	temp := filepath.Join(parent, "."+filepath.Base(destination)+"."+suffix+".partial")
	if err := writeNewFile(temp, data, 0o600); err != nil {
		return err
	}
	if err := renameNew(temp, destination); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

// ParseIdentityCard strictly validates an exported public identity card.
func ParseIdentityCard(raw []byte) (*IdentityCard, error) {
	var card IdentityCard
	if err := strictjson.UnmarshalExact(raw, &card); err != nil {
		return nil, err
	}
	if card.Schema != CardSchema || card.ProtocolVersion != ProtocolVersion || card.Genesis == nil ||
		card.IdentityID != card.Genesis.IdentityID || card.AdvisoryLabel != card.Genesis.AdvisoryLabel {
		return nil, fmt.Errorf("identity card fields are inconsistent")
	}
	if _, _, err := validateGenesis(card.Genesis); err != nil {
		return nil, err
	}
	return &card, nil
}

// ParseEvidenceAnchor strictly validates syntax. Pass it to
// ValidateEvidenceAnchor with lifecycle state to establish authority.
func ParseEvidenceAnchor(raw []byte) (*EvidenceAnchor, error) {
	var anchor EvidenceAnchor
	if err := strictjson.UnmarshalExact(raw, &anchor); err != nil {
		return nil, err
	}
	return &anchor, nil
}

// ParseLifecycleCheckpoint validates the complete recovery-root-authenticated
// chain carried by a checkpoint.
func ParseLifecycleCheckpoint(raw []byte) (*LifecycleCheckpoint, *State, error) {
	if len(raw) > 12*1024*1024 {
		return nil, nil, fmt.Errorf("identity: lifecycle checkpoint exceeds 12 MiB")
	}
	var checkpoint LifecycleCheckpoint
	if err := strictjson.UnmarshalExact(raw, &checkpoint); err != nil {
		return nil, nil, fmt.Errorf("identity: invalid lifecycle checkpoint: %w", err)
	}
	if checkpoint.Schema != CheckpointSchema || checkpoint.ProtocolVersion != ProtocolVersion || checkpoint.Genesis == nil ||
		checkpoint.IdentityID != checkpoint.Genesis.IdentityID || checkpoint.CheckpointSequence < 0 ||
		!hex64Pattern.MatchString(checkpoint.CheckpointDigest) || checkpoint.CheckpointSequence != len(checkpoint.LifecycleRecords)-1 {
		return nil, nil, fmt.Errorf("identity: lifecycle checkpoint fields are inconsistent")
	}
	state, err := DeriveState("", checkpoint.Genesis, checkpoint.LifecycleRecords)
	if err != nil {
		return nil, nil, err
	}
	if state.LastSequence != checkpoint.CheckpointSequence || state.LastRecordDigest != checkpoint.CheckpointDigest {
		return nil, nil, fmt.Errorf("identity: lifecycle checkpoint does not name its authenticated chain head")
	}
	return &checkpoint, state, nil
}

// ParseLifecycleNDJSON strictly parses a bounded public lifecycle chain from a
// bundle without touching local identity state.
func ParseLifecycleNDJSON(raw []byte) ([]*LifecycleRecord, error) {
	if len(raw) > 10*1024*1024 {
		return nil, fmt.Errorf("identity: lifecycle input exceeds 10 MiB")
	}
	var records []*LifecycleRecord
	for lineNumber, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(line) > 1024*1024 {
			return nil, fmt.Errorf("identity: lifecycle line %d exceeds 1 MiB", lineNumber+1)
		}
		var record LifecycleRecord
		if err := strictjson.UnmarshalExact([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("identity: lifecycle line %d: %w", lineNumber+1, err)
		}
		records = append(records, &record)
		if len(records) > 10000 {
			return nil, fmt.Errorf("identity: lifecycle contains more than 10000 records")
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("identity: lifecycle contains no records")
	}
	return records, nil
}

// ImportCheckpoint explicitly persists monotonic verifier state. Verification
// itself remains read-only; only this command mutates the chosen trust store.
func ImportCheckpoint(raw []byte, trustStore, expectedIdentity string) (*CheckpointImportResult, error) {
	checkpoint, _, err := ParseLifecycleCheckpoint(raw)
	if err != nil {
		return nil, err
	}
	if expectedIdentity == "" || checkpoint.IdentityID != expectedIdentity {
		return nil, fmt.Errorf("identity: checkpoint does not match the independently supplied identity pin")
	}
	trustStore, err = filepath.Abs(trustStore)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(trustStore, 0o700); err != nil {
		return nil, fmt.Errorf("identity: create explicit trust store: %w", err)
	}
	name := strings.TrimPrefix(expectedIdentity, "ueg:identity:sha256:") + ".checkpoint.json"
	destination := filepath.Join(trustStore, name)
	lock, err := filelock.Acquire(destination+".lock", os.O_RDWR|os.O_CREATE, 0o600, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("identity: lock checkpoint trust state: %w", err)
	}
	defer lock.Release()
	result := &CheckpointImportResult{
		IdentityID: checkpoint.IdentityID, Sequence: checkpoint.CheckpointSequence,
		Digest: checkpoint.CheckpointDigest, StoredPath: destination,
	}
	if existingRaw, readErr := os.ReadFile(destination); readErr == nil {
		existing, _, parseErr := ParseLifecycleCheckpoint(existingRaw)
		if parseErr != nil {
			return nil, fmt.Errorf("identity: stored checkpoint is invalid: %w", parseErr)
		}
		previous := existing.CheckpointSequence
		result.ReplacedSequence = &previous
		if checkpoint.CheckpointSequence < existing.CheckpointSequence {
			return nil, fmt.Errorf("identity: checkpoint rollback rejected (stored sequence %d, supplied %d)", existing.CheckpointSequence, checkpoint.CheckpointSequence)
		}
		if checkpoint.CheckpointSequence == existing.CheckpointSequence {
			if checkpoint.CheckpointDigest != existing.CheckpointDigest {
				return nil, fmt.Errorf("identity: same-sequence checkpoint conflict rejected")
			}
			return result, nil
		}
		if len(checkpoint.LifecycleRecords) <= existing.CheckpointSequence ||
			checkpoint.LifecycleRecords[existing.CheckpointSequence].RecordDigest != existing.CheckpointDigest {
			return nil, fmt.Errorf("identity: newer checkpoint is a fork, not a descendant of stored state")
		}
	} else if !os.IsNotExist(readErr) {
		return nil, readErr
	}
	if err := writeJSONAtomicReplace(destination, checkpoint, 0o600); err != nil {
		return nil, err
	}
	return result, nil
}

// LoadStoredCheckpoint reads retained verifier state without changing it.
func LoadStoredCheckpoint(trustStore, identityID string) (*LifecycleCheckpoint, *State, error) {
	if !identityIDPattern.MatchString(identityID) {
		return nil, nil, fmt.Errorf("identity: a complete genesis identity pin is required")
	}
	name := strings.TrimPrefix(identityID, "ueg:identity:sha256:") + ".checkpoint.json"
	raw, err := readBoundedRegular(filepath.Join(trustStore, name), 12*1024*1024)
	if err != nil {
		return nil, nil, err
	}
	return ParseLifecycleCheckpoint(raw)
}

// CompareLifecycleStates determines whether two authenticated views share one
// history and which view is newer. It never treats a same-sequence conflict as
// a tie.
func CompareLifecycleStates(local, external *State) (string, error) {
	if local == nil || external == nil || local.Genesis == nil || external.Genesis == nil {
		return "", fmt.Errorf("identity: two validated lifecycle states are required")
	}
	if local.Genesis.IdentityID != external.Genesis.IdentityID {
		return "", fmt.Errorf("identity: external checkpoint belongs to another identity")
	}
	common := len(local.Records)
	if len(external.Records) < common {
		common = len(external.Records)
	}
	for index := 0; index < common; index++ {
		if local.Records[index].RecordDigest != external.Records[index].RecordDigest {
			return "", fmt.Errorf("identity: lifecycle fork at sequence %d", index)
		}
	}
	switch {
	case local.LastSequence < external.LastSequence:
		return "LOCAL_STALE", nil
	case local.LastSequence > external.LastSequence:
		return "EXTERNAL_STALE", nil
	default:
		return "MATCH", nil
	}
}
