package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

const pendingSchema = "ueg.lifecycle-pending-transaction.v1"

// Tests use this nil-by-default hook to simulate abrupt process loss after a
// durable write. A panic bypasses normal cleanup, matching process termination.
var lifecycleMutationBoundary func(string)

func reachedMutationBoundary(name string) {
	if lifecycleMutationBoundary != nil {
		lifecycleMutationBoundary(name)
	}
}

type pendingTransaction struct {
	Schema               string           `json:"schema"`
	IdentityID           string           `json:"identity_id"`
	BaseSequence         int              `json:"base_sequence"`
	BaseRecordDigest     string           `json:"base_record_digest"`
	NewRecord            *LifecycleRecord `json:"new_record"`
	HasNewKey            bool             `json:"has_new_key"`
	NewEpoch             *int             `json:"new_epoch"`
	RemovePrivateEpoch   *int             `json:"remove_private_epoch"`
	LifecycleAfterSHA256 string           `json:"lifecycle_after_sha256"`
}

// ApplyMutation authenticates, journals, and completes one lifecycle mutation.
func ApplyMutation(home, recoveryPackage string, passphrase []byte, request MutationRequest) (*State, *LifecycleRecord, error) {
	state, err := LoadPublic(home)
	if err != nil {
		return nil, nil, err
	}
	if state.PendingMutation {
		return nil, nil, fmt.Errorf("identity: an interrupted lifecycle mutation requires transaction recovery")
	}
	root, _, err := OpenRecoveryPackage(recoveryPackage, passphrase, state.Genesis.IdentityID)
	if err != nil {
		return nil, nil, err
	}
	defer zero(root.Private)
	var current *keys.Pair
	var newPair *keys.Pair
	switch request.Action {
	case ActionRotate, ActionSuspend:
		signing, loadErr := LoadSigning(home)
		if loadErr != nil {
			return nil, nil, loadErr
		}
		current = signing.ActivePair
	case ActionResume:
		latest := state.Epochs[latestEpochNumber(state)]
		current, err = loadEpochPair(home, latest)
		if err != nil {
			return nil, nil, err
		}
	case ActionRecover:
		newPair, err = keys.Generate()
		if err != nil {
			return nil, nil, err
		}
	case ActionRevoke:
		// Root authority is deliberately sufficient for confirmed compromise.
	default:
		return nil, nil, fmt.Errorf("identity: unsupported mutation %q", request.Action)
	}
	if request.Action == ActionRotate {
		newPair, err = keys.Generate()
		if err != nil {
			return nil, nil, err
		}
	}
	record, err := NewLifecycleRecord(state, root, current, newPair, request)
	if err != nil {
		return nil, nil, err
	}
	candidateRecords := append(append([]*LifecycleRecord{}, state.Records...), record)
	if _, err := DeriveState(home, state.Genesis, candidateRecords); err != nil {
		return nil, nil, fmt.Errorf("identity: refusing invalid lifecycle transition: %w", err)
	}
	lifecycleAfter, err := marshalLifecycle(candidateRecords)
	if err != nil {
		return nil, nil, err
	}
	pending := &pendingTransaction{
		Schema: pendingSchema, IdentityID: state.Genesis.IdentityID,
		BaseSequence: state.LastSequence, BaseRecordDigest: state.LastRecordDigest,
		NewRecord: record, LifecycleAfterSHA256: canon.SHA256Hex(lifecycleAfter),
	}
	if newPair != nil {
		epoch := record.EpochNumber
		pending.HasNewKey = true
		pending.NewEpoch = &epoch
	}
	if record.Action == ActionRotate || record.Action == ActionRecover || record.Action == ActionRevoke {
		removeEpoch := latestEpochNumber(state)
		pending.RemovePrivateEpoch = &removeEpoch
	}
	if err := writeNewJSON(pendingPath(home), pending, 0o600); err != nil {
		return nil, nil, fmt.Errorf("identity: write lifecycle transaction journal: %w", err)
	}
	reachedMutationBoundary("journal_durable")
	if newPair != nil {
		if err := writePendingPair(home, record.EpochNumber, newPair); err != nil {
			_ = os.Remove(pendingPath(home))
			removePendingPair(home, pending)
			return nil, nil, err
		}
	}
	completed, err := RecoverPendingMutation(home)
	if err != nil {
		return nil, nil, err
	}
	return completed, record, nil
}

// RecoverPendingMutation completes the exact pre-signed transaction in the
// journal. It never needs or stores the recovery private key.
func RecoverPendingMutation(home string) (*State, error) {
	raw, err := readBoundedRegular(pendingPath(home), 2*1024*1024)
	if err != nil {
		if os.IsNotExist(err) {
			return LoadPublic(home)
		}
		return nil, fmt.Errorf("identity: read lifecycle transaction journal: %w", err)
	}
	var pending pendingTransaction
	if err := strictjson.UnmarshalExact(raw, &pending); err != nil {
		return nil, fmt.Errorf("identity: invalid lifecycle transaction journal: %w", err)
	}
	if pending.Schema != pendingSchema || pending.NewRecord == nil || pending.IdentityID == "" ||
		!hex64Pattern.MatchString(pending.BaseRecordDigest) || !hex64Pattern.MatchString(pending.LifecycleAfterSHA256) ||
		pending.HasNewKey != (pending.NewEpoch != nil) {
		return nil, fmt.Errorf("identity: lifecycle transaction journal fields are invalid")
	}
	state, err := loadPublicIgnoringPending(home)
	if err != nil {
		return nil, err
	}
	if state.Genesis.IdentityID != pending.IdentityID {
		return nil, fmt.Errorf("identity: lifecycle transaction journal names another identity")
	}
	alreadyApplied := state.LastSequence == pending.NewRecord.LifecycleSequence && state.LastRecordDigest == pending.NewRecord.RecordDigest
	if !alreadyApplied && (state.LastSequence != pending.BaseSequence || state.LastRecordDigest != pending.BaseRecordDigest) {
		return nil, fmt.Errorf("identity: lifecycle changed outside the pending transaction")
	}
	candidateRecords := state.Records
	if !alreadyApplied {
		candidateRecords = append(append([]*LifecycleRecord{}, state.Records...), pending.NewRecord)
	}
	candidate, err := DeriveState(home, state.Genesis, candidateRecords)
	if err != nil {
		return nil, fmt.Errorf("identity: pending lifecycle transition is invalid: %w", err)
	}
	lifecycleAfter, err := marshalLifecycle(candidateRecords)
	if err != nil {
		return nil, err
	}
	if canon.SHA256Hex(lifecycleAfter) != pending.LifecycleAfterSHA256 {
		return nil, fmt.Errorf("identity: pending lifecycle result hash does not match the journal")
	}
	if pending.HasNewKey {
		if !alreadyApplied && !completePendingOrFinalPair(home, *pending.NewEpoch) {
			removePendingPair(home, &pending)
			if err := os.Remove(pendingPath(home)); err != nil {
				return nil, fmt.Errorf("identity: roll back incomplete lifecycle transaction: %w", err)
			}
			return LoadPublic(home)
		}
		if err := publishPendingPair(home, *pending.NewEpoch, pending.NewRecord.OperationalKeyID); err != nil {
			return nil, err
		}
	}
	if !alreadyApplied {
		if err := writeAtomicReplace(lifecyclePath(home), lifecycleAfter, 0o600); err != nil {
			return nil, fmt.Errorf("identity: publish lifecycle transition: %w", err)
		}
		reachedMutationBoundary("lifecycle_published")
	}
	if pending.RemovePrivateEpoch != nil {
		path := epochPrivatePath(home, *pending.RemovePrivateEpoch)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("identity: retire old operational private key: %w", err)
		}
		reachedMutationBoundary("old_private_removed")
	}
	reachedMutationBoundary("before_journal_clear")
	if err := os.Remove(pendingPath(home)); err != nil {
		return nil, fmt.Errorf("identity: clear lifecycle transaction journal: %w", err)
	}
	if candidate.Active() != nil {
		return LoadSigning(home)
	}
	return LoadPublic(home)
}

// MutationPending reports the journal state without modifying it.
func MutationPending(home string) (bool, error) {
	_, err := os.Lstat(pendingPath(home))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func loadPublicIgnoringPending(home string) (*State, error) {
	temporary := pendingPath(home) + ".read-guard"
	if _, err := os.Lstat(temporary); err == nil {
		return nil, fmt.Errorf("identity: lifecycle recovery guard already exists")
	}
	// LoadPublic only marks pending after validating all authority. Reuse that
	// work, then clear the in-memory flag; no file is changed here.
	state, err := LoadPublic(home)
	if err != nil {
		return nil, err
	}
	state.PendingMutation = false
	return state, nil
}

func loadEpochPair(home string, epoch *EpochState) (*keys.Pair, error) {
	if epoch == nil {
		return nil, fmt.Errorf("identity: operational epoch is unavailable")
	}
	pair, err := keys.LoadExisting(epochPrivatePath(home, epoch.EpochNumber), epochPublicPath(home, epoch.EpochNumber))
	if err != nil {
		return nil, fmt.Errorf("identity: load operational epoch %d: %w", epoch.EpochNumber, err)
	}
	if pair.ValidateKeyID(epoch.OperationalKeyID, false) != nil {
		return nil, fmt.Errorf("identity: operational epoch %d private key does not match lifecycle", epoch.EpochNumber)
	}
	return pair, nil
}

func pendingPrivatePath(home string, epoch int) string {
	return epochPrivatePath(home, epoch) + ".pending"
}
func pendingPublicPath(home string, epoch int) string {
	return epochPublicPath(home, epoch) + ".pending"
}

func writePendingPair(home string, epoch int, pair *keys.Pair) error {
	if _, err := os.Lstat(epochDir(home, epoch)); err == nil {
		return fmt.Errorf("identity: epoch directory already exists: %d", epoch)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(epochDir(home, epoch), 0o700); err != nil {
		return err
	}
	if err := keys.PrepareProtectedDirectory(epochDir(home, epoch)); err != nil {
		return fmt.Errorf("identity: secure new operational-key directory: %w", err)
	}
	privatePEM, err := pair.PrivatePEM()
	if err != nil {
		return err
	}
	defer zero(privatePEM)
	if err := keys.WriteProtectedFile(pendingPrivatePath(home, epoch), privatePEM); err != nil {
		_ = os.RemoveAll(epochDir(home, epoch))
		return fmt.Errorf("identity: stage new operational private key: %w", err)
	}
	reachedMutationBoundary("new_private_staged")
	if err := pair.WritePublicFile(pendingPublicPath(home, epoch)); err != nil {
		_ = os.RemoveAll(epochDir(home, epoch))
		return fmt.Errorf("identity: stage new operational public key: %w", err)
	}
	reachedMutationBoundary("new_pair_staged")
	return nil
}

func publishPendingPair(home string, epoch int, expectedKeyID string) error {
	finalPrivate := epochPrivatePath(home, epoch)
	finalPublic := epochPublicPath(home, epoch)
	if _, err := os.Lstat(finalPrivate); os.IsNotExist(err) {
		if err := renameNew(pendingPrivatePath(home, epoch), finalPrivate); err != nil {
			return fmt.Errorf("identity: publish new operational private key: %w", err)
		}
		reachedMutationBoundary("new_private_published")
	} else if err != nil {
		return err
	}
	if _, err := os.Lstat(finalPublic); os.IsNotExist(err) {
		if err := renameNew(pendingPublicPath(home, epoch), finalPublic); err != nil {
			return fmt.Errorf("identity: publish new operational public key: %w", err)
		}
		reachedMutationBoundary("new_public_published")
	} else if err != nil {
		return err
	}
	pair, err := keys.LoadExisting(finalPrivate, finalPublic)
	if err != nil || pair.ValidateKeyID(expectedKeyID, false) != nil {
		return fmt.Errorf("identity: published operational key does not match the pending lifecycle record")
	}
	_ = os.Remove(pendingPrivatePath(home, epoch))
	_ = os.Remove(pendingPublicPath(home, epoch))
	return nil
}

func removePendingPair(home string, pending *pendingTransaction) {
	if pending == nil || pending.NewEpoch == nil {
		return
	}
	_ = os.RemoveAll(epochDir(home, *pending.NewEpoch))
}

func completePendingOrFinalPair(home string, epoch int) bool {
	pendingPrivate := fileExists(pendingPrivatePath(home, epoch))
	pendingPublic := fileExists(pendingPublicPath(home, epoch))
	finalPrivate := fileExists(epochPrivatePath(home, epoch))
	finalPublic := fileExists(epochPublicPath(home, epoch))
	return (pendingPrivate && pendingPublic) || (finalPrivate && finalPublic) ||
		(finalPrivate && pendingPublic) || (pendingPrivate && finalPublic)
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func validatePendingPath(home, path string) error {
	relative, err := filepath.Rel(home, path)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || (len(relative) > 3 && relative[:3] == ".."+string(filepath.Separator)) {
		return fmt.Errorf("identity: pending transaction path escapes the evidence home")
	}
	return nil
}

func marshalPending(pending *pendingTransaction) ([]byte, error) {
	return json.MarshalIndent(pending, "", "  ")
}
