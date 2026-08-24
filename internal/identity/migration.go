package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/filelock"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

const migrationSchema = "ueg.bplus-migration-transaction.v1"

var ErrMigrationRolledBack = errors.New("identity: incomplete migration was safely rolled back; legacy evidence remains unchanged")

// Tests use this nil-by-default hook to model abrupt process loss after each
// durable migration boundary. Production never assigns it.
var migrationMutationBoundary func(string)

func reachedMigrationBoundary(name string) {
	if migrationMutationBoundary != nil {
		migrationMutationBoundary(name)
	}
}

type migrationTransaction struct {
	Schema              string `json:"schema"`
	Home                string `json:"home"`
	IdentityID          string `json:"identity_id"`
	LegacyKeyID         string `json:"legacy_key_id"`
	StageHome           string `json:"stage_home"`
	RecoveryTemporary   string `json:"recovery_temporary"`
	RecoveryDestination string `json:"recovery_destination"`
	RecoverySHA256      string `json:"recovery_sha256"`
}

// MigrateLegacy performs explicit one-way enrollment of one verified legacy
// operational key. Callers must verify the legacy receipt ledger before this
// function and supply its exact head boundary.
func MigrateLegacy(home, recoveryDestination string, passphrase []byte, label, confirmedKeyID string, boundary LedgerBoundary) (*State, error) {
	home, err := filepath.Abs(home)
	if err != nil {
		return nil, err
	}
	lock, err := filelock.Acquire(
		filepath.Join(home, migrationLock),
		os.O_RDWR|os.O_CREATE,
		0o600,
		30*time.Second,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: lock legacy migration: %w", err)
	}
	defer lock.Release()
	if pending, pendingErr := MigrationPending(home); pendingErr != nil {
		return nil, pendingErr
	} else if pending {
		state, recoverErr := recoverPendingMigrationLocked(home)
		if recoverErr == nil {
			return state, nil
		}
		if !errors.Is(recoverErr, ErrMigrationRolledBack) {
			return nil, recoverErr
		}
	}
	if IsBPlus(home) {
		return nil, fmt.Errorf("identity: evidence home is already B+")
	}
	if err := validateBoundary(boundary); err != nil {
		return nil, err
	}
	recoveryDestination, err = filepath.Abs(recoveryDestination)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(recoveryDestination); err == nil {
		return nil, fmt.Errorf("identity: recovery-package destination already exists: %s", recoveryDestination)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if info, statErr := os.Stat(filepath.Dir(recoveryDestination)); statErr != nil || !info.IsDir() {
		return nil, fmt.Errorf("identity: recovery-package destination parent is not an existing directory")
	}
	if relative, relErr := filepath.Rel(home, recoveryDestination); relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("identity: recovery package must be outside the evidence home")
	}
	if fileExists(markerPath(home)) || fileExists(filepath.Join(home, migrationPending)) {
		return nil, fmt.Errorf("identity: migration authority already exists")
	}
	if _, statErr := os.Lstat(identityDir(home)); statErr == nil {
		return nil, fmt.Errorf("identity: undeclared identity directory blocks migration")
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}
	legacy, err := keys.LoadExisting(legacyPrivatePath(home), legacyPublicPath(home))
	if err != nil {
		return nil, fmt.Errorf("identity: load verified legacy signing key: %w", err)
	}
	if confirmedKeyID == "" || legacy.ValidateKeyID(confirmedKeyID, false) != nil {
		return nil, fmt.Errorf("identity: owner-confirmed legacy fingerprint does not match")
	}
	root, err := keys.Generate()
	if err != nil {
		return nil, err
	}
	defer zero(root.Private)
	genesis, firstRecord, err := NewGenesis(root, legacy, label, ActionMigration, boundary)
	if err != nil {
		return nil, err
	}
	packageBytes, err := encryptRecoveryPackage(genesis.IdentityID, root, passphrase)
	if err != nil {
		return nil, err
	}
	defer zero(packageBytes)
	suffix, err := randomSuffix()
	if err != nil {
		return nil, err
	}
	stageHome := filepath.Join(filepath.Dir(home), "."+filepath.Base(home)+".ueg-migrate-"+suffix)
	packageTemp := filepath.Join(filepath.Dir(recoveryDestination), "."+filepath.Base(recoveryDestination)+".ueg-migrate-"+suffix+".partial")
	txn := &migrationTransaction{
		Schema: migrationSchema, Home: home, IdentityID: genesis.IdentityID,
		LegacyKeyID: confirmedKeyID, StageHome: stageHome,
		RecoveryTemporary: packageTemp, RecoveryDestination: recoveryDestination,
		RecoverySHA256: canon.SHA256Hex(append(append([]byte{}, packageBytes...), '\n')),
	}
	if err := writeNewJSON(filepath.Join(home, migrationPending), txn, 0o600); err != nil {
		return nil, fmt.Errorf("identity: write migration transaction journal: %w", err)
	}
	reachedMigrationBoundary("journal_durable")
	if err := keys.WriteProtectedFile(packageTemp, append(packageBytes, '\n')); err != nil {
		return nil, fmt.Errorf("identity: stage recovery package: %w", err)
	}
	if _, err := VerifyRecoveryPackage(packageTemp, passphrase, genesis.IdentityID); err != nil {
		return nil, fmt.Errorf("identity: staged recovery package failed restore/signing test: %w", err)
	}
	reachedMigrationBoundary("recovery_package_staged")
	if err := writeStagedHome(stageHome, genesis, firstRecord, legacy); err != nil {
		return nil, fmt.Errorf("identity: stage B+ authority: %w", err)
	}
	reachedMigrationBoundary("authority_staged")
	return completeMigration(txn)
}

// MigrationPending reports an explicit migration journal without changing it.
func MigrationPending(home string) (bool, error) {
	_, err := os.Lstat(filepath.Join(home, migrationPending))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// RecoverPendingMigration completes a fully staged migration or rolls back an
// early interruption while the legacy private key is still authoritative.
func RecoverPendingMigration(home string) (*State, error) {
	home, err := filepath.Abs(home)
	if err != nil {
		return nil, err
	}
	lock, err := filelock.Acquire(
		filepath.Join(home, migrationLock),
		os.O_RDWR|os.O_CREATE,
		0o600,
		30*time.Second,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: lock legacy migration recovery: %w", err)
	}
	defer lock.Release()
	return recoverPendingMigrationLocked(home)
}

func recoverPendingMigrationLocked(home string) (*State, error) {
	raw, err := readBoundedRegular(filepath.Join(home, migrationPending), 128*1024)
	if err != nil {
		return nil, err
	}
	var txn migrationTransaction
	if err := strictjson.UnmarshalExact(raw, &txn); err != nil {
		return nil, fmt.Errorf("identity: invalid migration transaction journal: %w", err)
	}
	if err := validateMigrationTransaction(home, &txn); err != nil {
		return nil, err
	}
	if IsBPlus(home) {
		state, loadErr := LoadSigning(home)
		if loadErr != nil {
			return nil, fmt.Errorf("identity: published migration is not valid: %w", loadErr)
		}
		if err := cleanupCompletedMigration(&txn); err != nil {
			return nil, err
		}
		return state, nil
	}
	packageReady := validMigrationPackageFile(txn.RecoveryTemporary, &txn) || validMigrationPackageFile(txn.RecoveryDestination, &txn)
	stageReady := validMigrationStage(&txn)
	identityReady := validPublishedIdentity(&txn)
	legacyAvailable := fileExists(legacyPrivatePath(home))
	quarantineAvailable := fileExists(migrationQuarantinePath(home))
	if !packageReady || (!stageReady && !identityReady) {
		if legacyAvailable && !quarantineAvailable && !fileExists(markerPath(home)) && !fileExists(filepath.Join(home, markerName)) {
			_ = os.RemoveAll(txn.StageHome)
			_ = os.Remove(txn.RecoveryTemporary)
			_ = os.Remove(filepath.Join(home, migrationPending))
			return nil, ErrMigrationRolledBack
		}
		return nil, fmt.Errorf("identity: migration cannot be completed or safely rolled back; preserve the journal and staged files")
	}
	return completeMigration(&txn)
}

func completeMigration(txn *migrationTransaction) (*State, error) {
	home := txn.Home
	if !fileExists(migrationQuarantinePath(home)) {
		if !fileExists(legacyPrivatePath(home)) {
			return nil, fmt.Errorf("identity: legacy operational private key is unavailable")
		}
		if err := renameNew(legacyPrivatePath(home), migrationQuarantinePath(home)); err != nil {
			return nil, fmt.Errorf("identity: disable legacy signing path: %w", err)
		}
		reachedMigrationBoundary("legacy_key_quarantined")
	}
	if !validMigrationPackageFile(txn.RecoveryDestination, txn) {
		if !validMigrationPackageFile(txn.RecoveryTemporary, txn) {
			return nil, fmt.Errorf("identity: exact staged recovery package is unavailable")
		}
		if err := renameNew(txn.RecoveryTemporary, txn.RecoveryDestination); err != nil {
			return nil, fmt.Errorf("identity: publish recovery package: %w", err)
		}
		reachedMigrationBoundary("recovery_package_published")
	}
	if _, err := os.Lstat(identityDir(home)); os.IsNotExist(err) {
		if !validMigrationStage(txn) {
			return nil, fmt.Errorf("identity: staged authority is unavailable")
		}
		if err := renameNew(identityDir(txn.StageHome), identityDir(home)); err != nil {
			return nil, fmt.Errorf("identity: publish lifecycle authority: %w", err)
		}
		reachedMigrationBoundary("identity_authority_published")
	} else if err != nil {
		return nil, err
	}
	if !fileExists(markerPath(home)) {
		stageMarker := markerPath(txn.StageHome)
		if !fileExists(stageMarker) {
			return nil, fmt.Errorf("identity: staged B+ marker is unavailable")
		}
		if err := renameNew(stageMarker, markerPath(home)); err != nil {
			return nil, fmt.Errorf("identity: publish B+ marker: %w", err)
		}
		reachedMigrationBoundary("marker_published")
	}
	state, err := LoadSigning(home)
	if err != nil {
		return nil, fmt.Errorf("identity: migrated home failed verification: %w", err)
	}
	if state.Genesis.IdentityID != txn.IdentityID || state.Genesis.EpochZeroKeyID != txn.LegacyKeyID {
		return nil, fmt.Errorf("identity: migrated authority does not match the journal")
	}
	reachedMigrationBoundary("before_cleanup")
	if err := cleanupCompletedMigration(txn); err != nil {
		return nil, err
	}
	return state, nil
}

func validateMigrationTransaction(home string, txn *migrationTransaction) error {
	if txn.Schema != migrationSchema || txn.Home != home || !identityIDPattern.MatchString(txn.IdentityID) ||
		!keyIDPattern.MatchString(txn.LegacyKeyID) || !hex64Pattern.MatchString(txn.RecoverySHA256) {
		return fmt.Errorf("identity: migration transaction fields are invalid")
	}
	if filepath.Dir(txn.StageHome) != filepath.Dir(home) || !strings.HasPrefix(filepath.Base(txn.StageHome), "."+filepath.Base(home)+".ueg-migrate-") {
		return fmt.Errorf("identity: migration stage path is not bound to the evidence home")
	}
	if filepath.Dir(txn.RecoveryTemporary) != filepath.Dir(txn.RecoveryDestination) ||
		!strings.HasPrefix(filepath.Base(txn.RecoveryTemporary), "."+filepath.Base(txn.RecoveryDestination)+".ueg-migrate-") {
		return fmt.Errorf("identity: migration recovery path is invalid")
	}
	if relative, err := filepath.Rel(home, txn.RecoveryDestination); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("identity: migration recovery package points inside the evidence home")
	}
	return nil
}

func validMigrationPackageFile(path string, txn *migrationTransaction) bool {
	raw, err := readBoundedRegular(path, 1024*1024)
	if err != nil || canon.SHA256Hex(raw) != txn.RecoverySHA256 {
		return false
	}
	var pkg RecoveryPackage
	if strictjson.UnmarshalExact(raw, &pkg) != nil {
		return false
	}
	return pkg.Schema == RecoverySchema && pkg.ProtocolVersion == ProtocolVersion && pkg.IdentityID == txn.IdentityID
}

func validMigrationStage(txn *migrationTransaction) bool {
	state, err := LoadSigning(txn.StageHome)
	return err == nil && state.Genesis.IdentityID == txn.IdentityID && state.Genesis.EpochZeroKeyID == txn.LegacyKeyID
}

func validPublishedIdentity(txn *migrationTransaction) bool {
	genesisRaw, err := readBoundedRegular(genesisPath(txn.Home), 1024*1024)
	if err != nil {
		return false
	}
	var genesis Genesis
	return strictjson.UnmarshalExact(genesisRaw, &genesis) == nil && genesis.IdentityID == txn.IdentityID && genesis.EpochZeroKeyID == txn.LegacyKeyID
}

func cleanupCompletedMigration(txn *migrationTransaction) error {
	for _, path := range []string{migrationQuarantinePath(txn.Home), txn.RecoveryTemporary, filepath.Join(txn.Home, migrationPending)} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("identity: clean completed migration state: %w", err)
		}
	}
	if err := os.RemoveAll(txn.StageHome); err != nil {
		return fmt.Errorf("identity: clean migration stage: %w", err)
	}
	return nil
}

func migrationQuarantinePath(home string) string {
	return filepath.Join(home, "keys", ".ed25519_private.migration.pem")
}

func marshalMigration(txn *migrationTransaction) ([]byte, error) {
	return json.MarshalIndent(txn, "", "  ")
}
