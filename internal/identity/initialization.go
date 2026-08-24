package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

const initializationPendingSchema = "ueg.bplus-initialization-transaction.v1"

var ErrInitializationRolledBack = errors.New("identity: incomplete initialization was safely rolled back; no evidence identity was created")

// Tests use this nil-by-default hook to model abrupt process loss after each
// durable initialization boundary. Production never assigns it.
var initializationMutationBoundary func(string)

func reachedInitializationBoundary(name string) {
	if initializationMutationBoundary != nil {
		initializationMutationBoundary(name)
	}
}

type initializationTransaction struct {
	Schema              string `json:"schema"`
	Home                string `json:"home"`
	IdentityID          string `json:"identity_id"`
	StageHome           string `json:"stage_home"`
	RecoveryTemporary   string `json:"recovery_temporary"`
	RecoveryDestination string `json:"recovery_destination"`
	RecoverySHA256      string `json:"recovery_sha256"`
}

func initializationPendingPath(home string) string {
	return filepath.Join(filepath.Dir(home), "."+filepath.Base(home)+".ueg-init.pending.json")
}

// InitializationPending reports a genesis transaction without changing it.
func InitializationPending(home string) (bool, error) {
	absolute, err := filepath.Abs(home)
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(initializationPendingPath(absolute))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func writeInitializationJournal(txn *initializationTransaction) error {
	if err := writeNewJSON(initializationPendingPath(txn.Home), txn, 0o600); err != nil {
		return fmt.Errorf("identity: write initialization transaction journal: %w", err)
	}
	reachedInitializationBoundary("journal_durable")
	return nil
}

// RecoverPendingInitialization completes a fully staged genesis or removes an
// early, unpublished transaction. A nil passphrase is allowed because the
// staged home is created only after the recovery package restore/signing test
// has passed. A supplied passphrase repeats that test after publication.
func RecoverPendingInitialization(home string, passphrase []byte) (*State, error) {
	home, err := filepath.Abs(home)
	if err != nil {
		return nil, err
	}
	raw, err := readBoundedRegular(initializationPendingPath(home), 128*1024)
	if err != nil {
		return nil, err
	}
	var txn initializationTransaction
	if err := strictjson.UnmarshalExact(raw, &txn); err != nil {
		return nil, fmt.Errorf("identity: invalid initialization transaction journal: %w", err)
	}
	if err := validateInitializationTransaction(home, &txn); err != nil {
		return nil, err
	}
	if IsBPlus(home) {
		state, loadErr := LoadSigning(home)
		if loadErr != nil || state.Genesis.IdentityID != txn.IdentityID {
			return nil, fmt.Errorf("identity: published initialization is not valid: %w", loadErr)
		}
		if len(passphrase) != 0 {
			if _, verifyErr := VerifyRecoveryPackage(txn.RecoveryDestination, passphrase, txn.IdentityID); verifyErr != nil {
				return nil, fmt.Errorf("identity: published recovery package failed restore/signing test: %w", verifyErr)
			}
		}
		if err := cleanupCompletedInitialization(&txn); err != nil {
			return nil, err
		}
		return state, nil
	}
	packageReady := validInitializationPackageFile(txn.RecoveryTemporary, &txn) || validInitializationPackageFile(txn.RecoveryDestination, &txn)
	stageReady := validInitializationStage(&txn)
	if !packageReady || !stageReady {
		if _, destinationErr := os.Lstat(txn.RecoveryDestination); os.IsNotExist(destinationErr) {
			_ = os.RemoveAll(txn.StageHome)
			_ = os.Remove(txn.RecoveryTemporary)
			_ = os.Remove(initializationPendingPath(home))
			return nil, ErrInitializationRolledBack
		}
		return nil, fmt.Errorf("identity: initialization cannot be completed or safely rolled back; preserve the journal and staged files")
	}
	return completeInitialization(&txn, passphrase)
}

func completeInitialization(txn *initializationTransaction, passphrase []byte) (*State, error) {
	if !validInitializationPackageFile(txn.RecoveryDestination, txn) {
		if !validInitializationPackageFile(txn.RecoveryTemporary, txn) {
			return nil, fmt.Errorf("identity: exact staged recovery package is unavailable")
		}
		if err := renameNew(txn.RecoveryTemporary, txn.RecoveryDestination); err != nil {
			return nil, fmt.Errorf("identity: publish recovery package: %w", err)
		}
		reachedInitializationBoundary("recovery_package_published")
	}
	if !IsBPlus(txn.Home) {
		if !validInitializationStage(txn) {
			return nil, fmt.Errorf("identity: exact staged evidence identity is unavailable")
		}
		if err := renameNew(txn.StageHome, txn.Home); err != nil {
			return nil, fmt.Errorf("identity: publish evidence home: %w", err)
		}
		reachedInitializationBoundary("home_published")
	}
	state, err := LoadSigning(txn.Home)
	if err != nil || state.Genesis.IdentityID != txn.IdentityID {
		return nil, fmt.Errorf("identity: initialized home did not verify: %w", err)
	}
	if len(passphrase) != 0 {
		if _, err := VerifyRecoveryPackage(txn.RecoveryDestination, passphrase, txn.IdentityID); err != nil {
			return nil, fmt.Errorf("identity: published recovery package failed restore/signing test: %w", err)
		}
	}
	reachedInitializationBoundary("before_cleanup")
	if err := cleanupCompletedInitialization(txn); err != nil {
		return nil, err
	}
	return state, nil
}

func validateInitializationTransaction(home string, txn *initializationTransaction) error {
	if txn.Schema != initializationPendingSchema || txn.Home != home || !identityIDPattern.MatchString(txn.IdentityID) ||
		!hex64Pattern.MatchString(txn.RecoverySHA256) {
		return fmt.Errorf("identity: initialization transaction fields are invalid")
	}
	if filepath.Dir(txn.StageHome) != filepath.Dir(home) || !strings.HasPrefix(filepath.Base(txn.StageHome), "."+filepath.Base(home)+".ueg-init-") {
		return fmt.Errorf("identity: initialization stage path is not bound to the evidence home")
	}
	if filepath.Dir(txn.RecoveryTemporary) != filepath.Dir(txn.RecoveryDestination) ||
		!strings.HasPrefix(filepath.Base(txn.RecoveryTemporary), "."+filepath.Base(txn.RecoveryDestination)+".ueg-init-") {
		return fmt.Errorf("identity: initialization recovery path is invalid")
	}
	if relative, err := filepath.Rel(home, txn.RecoveryDestination); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("identity: initialization recovery package points inside the evidence home")
	}
	return nil
}

func validInitializationPackageFile(path string, txn *initializationTransaction) bool {
	raw, err := readBoundedRegular(path, 1024*1024)
	if err != nil || canon.SHA256Hex(raw) != txn.RecoverySHA256 {
		return false
	}
	var pkg RecoveryPackage
	return strictjson.UnmarshalExact(raw, &pkg) == nil && pkg.Schema == RecoverySchema &&
		pkg.ProtocolVersion == ProtocolVersion && pkg.IdentityID == txn.IdentityID
}

func validInitializationStage(txn *initializationTransaction) bool {
	state, err := LoadSigning(txn.StageHome)
	return err == nil && state.Genesis.IdentityID == txn.IdentityID
}

func cleanupCompletedInitialization(txn *initializationTransaction) error {
	for _, path := range []string{txn.RecoveryTemporary, initializationPendingPath(txn.Home)} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("identity: clean completed initialization state: %w", err)
		}
	}
	if err := os.RemoveAll(txn.StageHome); err != nil {
		return fmt.Errorf("identity: clean initialization stage: %w", err)
	}
	return nil
}
