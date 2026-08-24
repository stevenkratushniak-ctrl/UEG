package identity_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stevenkratushniak-ctrl/ueg/internal/identity"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
)

func TestLegacyMigrationPreservesEvidenceAndDisablesV2Signing(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "legacy-home")
	recoveryDir := filepath.Join(root, "offline")
	if err := os.Mkdir(recoveryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	recovery := filepath.Join(recoveryDir, "recovery.json")
	legacy, err := ledger.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := legacy.Append(
		ledger.Petition{"action": "qualification", "target": "synthetic"},
		ledger.PetitionSummary{Surface: "qualification", Action: "qualification", Target: "synthetic"},
		"ueg:test", "ADMITTED", "SILENT", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []string{"qualification"},
	)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := legacy.KeyID
	boundary := identity.LedgerBoundary{SequenceNo: receipt.SequenceNo, ReceiptID: &receipt.ReceiptID}
	state, err := identity.MigrateLegacy(home, recovery, []byte("test-only migration passphrase"), "migrated ledger", confirmed, boundary)
	if err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if state.Genesis.EpochZeroKeyID != confirmed || state.Records[0].Action != identity.ActionMigration {
		t.Fatalf("legacy key was not enrolled as epoch zero: %#v", state.Records[0])
	}
	if _, err := os.Stat(filepath.Join(home, "keys", "ed25519_private.pem")); !os.IsNotExist(err) {
		t.Fatalf("legacy private-key path survived migration: %v", err)
	}
	if _, err := keys.LoadOrCreate(
		filepath.Join(home, "keys", "ed25519_private.pem"),
		filepath.Join(home, "keys", "ed25519_public.pem"),
	); err == nil {
		t.Fatal("legacy v2 key-open path did not fail closed after migration")
	}
	reopened, err := ledger.OpenReadOnly(home)
	if err != nil {
		t.Fatalf("open migrated ledger: %v", err)
	}
	if result := reopened.VerifyReceipts(); !result.OK || result.Checked != 1 {
		t.Fatalf("historical receipt did not verify after migration: %#v", result)
	}
	if _, err := identity.VerifyRecoveryPackage(recovery, []byte("test-only migration passphrase"), state.Genesis.IdentityID); err != nil {
		t.Fatalf("migrated recovery package: %v", err)
	}
}

func TestLegacyMigrationRequiresExactOwnerConfirmedFingerprint(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "legacy-home")
	if _, err := ledger.Open(home); err != nil {
		t.Fatal(err)
	}
	offline := filepath.Join(root, "offline")
	if err := os.Mkdir(offline, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := identity.MigrateLegacy(
		home, filepath.Join(offline, "recovery.json"), []byte("test-only migration passphrase"), "",
		"ueg:sha256:0000000000000000000000000000000000000000000000000000000000000000",
		identity.LedgerBoundary{SequenceNo: -1},
	)
	if err == nil {
		t.Fatal("migration accepted a mismatched owner-confirmed fingerprint")
	}
	if identity.IsBPlus(home) {
		t.Fatal("failed migration changed the legacy home format")
	}
}

func TestConcurrentLegacyMigrationsAreSerialized(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "legacy-home")
	legacy, err := ledger.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	offline := filepath.Join(root, "offline")
	if err := os.Mkdir(offline, 0o700); err != nil {
		t.Fatal(err)
	}
	destinations := []string{
		filepath.Join(offline, "recovery-a.json"),
		filepath.Join(offline, "recovery-b.json"),
	}

	start := make(chan struct{})
	results := make(chan error, len(destinations))
	var workers sync.WaitGroup
	for index := range destinations {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			_, migrateErr := identity.MigrateLegacy(
				home,
				destinations[index],
				[]byte("test-only migration passphrase"),
				"concurrent migration",
				legacy.KeyID,
				identity.LedgerBoundary{SequenceNo: -1},
			)
			results <- migrateErr
		}(index)
	}
	close(start)
	workers.Wait()
	close(results)

	successes := 0
	for result := range results {
		if result == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent migrations produced %d successes, want exactly one", successes)
	}
	if !identity.IsBPlus(home) {
		t.Fatal("serialized migration did not publish B+ authority")
	}
	if pending, pendingErr := identity.MigrationPending(home); pendingErr != nil || pending {
		t.Fatalf("serialized migration left pending state: pending=%v err=%v", pending, pendingErr)
	}
}
