// Package identity implements UEG B+ authenticated evidence epochs.
package identity

import (
	"crypto/ed25519"

	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
)

const (
	ProtocolVersion  = "ueg-bplus/1"
	GenesisSchema    = "ueg.identity-genesis.v1"
	LifecycleSchema  = "ueg.identity-lifecycle-record.v1"
	MarkerSchema     = "ueg.identity-home.v1"
	RecoverySchema   = "ueg.recovery-package.v1"
	CardSchema       = "ueg.identity-card.v1"
	AnchorSchema     = "ueg.evidence-anchor.v1"
	CheckpointSchema = "ueg.lifecycle-checkpoint.v1"

	StatusActive    = "ACTIVE"
	StatusRetired   = "RETIRED"
	StatusSuspended = "SUSPENDED"
	StatusRevoked   = "REVOKED"

	ActionGenesis   = "GENESIS"
	ActionMigration = "MIGRATION"
	ActionRotate    = "ROTATE"
	ActionRecover   = "RECOVER"
	ActionSuspend   = "SUSPEND"
	ActionResume    = "RESUME"
	ActionRevoke    = "REVOKE"
)

const (
	genesisDomain = "UEG-BPLUS-GENESIS-v1"
	recordDomain  = "UEG-BPLUS-LIFECYCLE-v1"
	anchorDomain  = "UEG-BPLUS-EVIDENCE-ANCHOR-v1"
)

// GenesisPolicy is cryptographic policy, not an advisory product setting.
type GenesisPolicy struct {
	OneActiveOperationalKey bool `json:"one_active_operational_key"`
	ConcurrentSigning       bool `json:"concurrent_signing"`
	RecoveryRootRotation    bool `json:"recovery_root_rotation"`
}

// Genesis is the stable public identity authority. identity_id is the digest
// of the canonical genesis body; signatures are over that body plus identity_id.
type Genesis struct {
	Schema                   string        `json:"schema"`
	ProtocolVersion          string        `json:"protocol_version"`
	IdentityNonceB64         string        `json:"identity_nonce_b64"`
	RecoveryRootKeyID        string        `json:"recovery_root_key_id"`
	RecoveryRootPublicKeyPEM string        `json:"recovery_root_public_key_pem"`
	EpochZeroKeyID           string        `json:"epoch_zero_key_id"`
	EpochZeroPublicKeyPEM    string        `json:"epoch_zero_public_key_pem"`
	Canonicalization         string        `json:"canonicalization"`
	GenesisPolicy            GenesisPolicy `json:"genesis_policy"`
	AdvisoryLabel            string        `json:"advisory_label"`
	IdentityID               string        `json:"identity_id"`
	RecoverySignatureB64     string        `json:"recovery_signature_b64"`
	EpochZeroProofB64        string        `json:"epoch_zero_proof_b64"`
}

// LedgerBoundary names an exact chain head. SequenceNo is -1 and ReceiptID is
// nil for an empty ledger.
type LedgerBoundary struct {
	SequenceNo int     `json:"sequence_no"`
	ReceiptID  *string `json:"receipt_id"`
}

// PreviousEpoch records the epoch closed by a transition.
type PreviousEpoch struct {
	EpochNumber         int            `json:"epoch_number"`
	OperationalKeyID    string         `json:"operational_key_id"`
	OperationalStatus   string         `json:"operational_status"`
	FinalLedgerBoundary LedgerBoundary `json:"final_ledger_boundary"`
}

// LifecycleRecord is a recovery-root-authenticated state transition. Nullable
// fields remain explicit on the wire so omitted and null cannot be confused.
type LifecycleRecord struct {
	Schema                  string         `json:"schema"`
	ProtocolVersion         string         `json:"protocol_version"`
	IdentityID              string         `json:"identity_id"`
	LifecycleSequence       int            `json:"lifecycle_sequence"`
	PreviousRecordDigest    *string        `json:"previous_record_digest"`
	Action                  string         `json:"action"`
	EpochNumber             int            `json:"epoch_number"`
	OperationalKeyID        string         `json:"operational_key_id"`
	OperationalPublicKeyPEM string         `json:"operational_public_key_pem"`
	OperationalStatus       string         `json:"operational_status"`
	LedgerBoundary          LedgerBoundary `json:"ledger_boundary"`
	PreviousEpoch           *PreviousEpoch `json:"previous_epoch"`
	EvidenceAnchorDigest    *string        `json:"evidence_anchor_digest"`
	ReasonCode              string         `json:"reason_code"`
	RecordDigest            string         `json:"record_digest"`
	RecoverySignatureB64    string         `json:"recovery_signature_b64"`
	RetiringSignatureB64    *string        `json:"retiring_signature_b64"`
	OperationalProofB64     *string        `json:"operational_proof_b64"`
}

// Marker makes the evidence-home format explicit and causes new code to avoid
// treating a B+ home as a legacy single-key home.
type Marker struct {
	Schema          string `json:"schema"`
	ProtocolVersion string `json:"protocol_version"`
	IdentityID      string `json:"identity_id"`
}

// AuthorizationWindow is a half-open ledger interval: receipts after
// StartAfter through EndAt (inclusive) are authorized by this epoch.
type AuthorizationWindow struct {
	StartAfter LedgerBoundary  `json:"start_after"`
	EndAt      *LedgerBoundary `json:"end_at"`
}

// EpochState is the lifecycle-derived state of one operational epoch.
type EpochState struct {
	EpochNumber          int                   `json:"epoch_number"`
	OperationalKeyID     string                `json:"operational_key_id"`
	OperationalPublicPEM string                `json:"operational_public_key_pem"`
	Status               string                `json:"status"`
	Windows              []AuthorizationWindow `json:"authorization_windows"`
	KnownGoodAnchor      *string               `json:"known_good_anchor_digest"`
}

// State is validated public lifecycle state plus, for signing opens, the one
// active operational private key.
type State struct {
	Home             string
	Genesis          *Genesis
	Records          []*LifecycleRecord
	Epochs           map[int]*EpochState
	Trust            map[string]*keys.Pair
	RecoveryPublic   *keys.Pair
	ActiveEpoch      *int
	ActivePair       *keys.Pair
	LastSequence     int
	LastRecordDigest string
	PendingMutation  bool
}

// Active returns the current active epoch or nil.
func (s *State) Active() *EpochState {
	if s == nil || s.ActiveEpoch == nil {
		return nil
	}
	return s.Epochs[*s.ActiveEpoch]
}

// MutationRequest describes one root-authorized lifecycle operation.
type MutationRequest struct {
	Action               string
	ReasonCode           string
	Boundary             LedgerBoundary
	EvidenceAnchorDigest *string
}

// RecoveryPackage is an encrypted offline recovery-root container.
type RecoveryPackage struct {
	Schema            string         `json:"schema"`
	ProtocolVersion   string         `json:"protocol_version"`
	IdentityID        string         `json:"identity_id"`
	RecoveryRootKeyID string         `json:"recovery_root_key_id"`
	KDF               RecoveryKDF    `json:"kdf"`
	Cipher            RecoveryCipher `json:"cipher"`
	CiphertextB64     string         `json:"ciphertext_b64"`
}

type RecoveryKDF struct {
	Name        string `json:"name"`
	SaltB64     string `json:"salt_b64"`
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
	KeyBytes    uint32 `json:"key_bytes"`
}

type RecoveryCipher struct {
	Name     string `json:"name"`
	NonceB64 string `json:"nonce_b64"`
}

type recoveryPayload struct {
	Schema                string `json:"schema"`
	IdentityID            string `json:"identity_id"`
	RecoveryRootKeyID     string `json:"recovery_root_key_id"`
	RecoveryPrivateKeyPEM string `json:"recovery_private_key_pem"`
}

// IdentityCard is safe to distribute. It contains no private material.
type IdentityCard struct {
	Schema          string   `json:"schema"`
	ProtocolVersion string   `json:"protocol_version"`
	IdentityID      string   `json:"identity_id"`
	AdvisoryLabel   string   `json:"advisory_label"`
	Genesis         *Genesis `json:"genesis"`
}

// EvidenceAnchor is an operational-key-signed exact ledger head.
type EvidenceAnchor struct {
	Schema                string         `json:"schema"`
	ProtocolVersion       string         `json:"protocol_version"`
	IdentityID            string         `json:"identity_id"`
	EpochNumber           int            `json:"epoch_number"`
	OperationalKeyID      string         `json:"operational_key_id"`
	LedgerBoundary        LedgerBoundary `json:"ledger_boundary"`
	LifecycleSequence     int            `json:"lifecycle_sequence"`
	LifecycleRecordDigest string         `json:"lifecycle_record_digest"`
	AnchorDigest          string         `json:"anchor_digest"`
	SignatureB64          string         `json:"signature_b64"`
}

// LifecycleCheckpoint is a public, recovery-root-authenticated lifecycle
// snapshot. Authenticity comes from the validated record chain it carries.
type LifecycleCheckpoint struct {
	Schema             string             `json:"schema"`
	ProtocolVersion    string             `json:"protocol_version"`
	IdentityID         string             `json:"identity_id"`
	Genesis            *Genesis           `json:"genesis"`
	LifecycleRecords   []*LifecycleRecord `json:"lifecycle_records"`
	CheckpointSequence int                `json:"checkpoint_sequence"`
	CheckpointDigest   string             `json:"checkpoint_digest"`
}

// CheckpointImportResult describes an explicit verifier-state mutation.
type CheckpointImportResult struct {
	IdentityID       string `json:"identity_id"`
	Sequence         int    `json:"checkpoint_sequence"`
	Digest           string `json:"checkpoint_digest"`
	StoredPath       string `json:"stored_path"`
	ReplacedSequence *int   `json:"replaced_sequence"`
}

func publicOnly(public ed25519.PublicKey) *keys.Pair {
	return &keys.Pair{Public: append(ed25519.PublicKey(nil), public...)}
}
