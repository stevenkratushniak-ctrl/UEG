package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
)

func TestMigrationRecoversAtEveryDurableMutationBoundary(t *testing.T) {
	boundaries := []string{
		"journal_durable",
		"recovery_package_staged",
		"authority_staged",
		"legacy_key_quarantined",
		"recovery_package_published",
		"identity_authority_published",
		"marker_published",
		"before_cleanup",
	}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "legacy-home")
			offline := filepath.Join(root, "offline")
			if err := os.MkdirAll(filepath.Join(home, "keys"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(offline, 0o700); err != nil {
				t.Fatal(err)
			}
			legacy, err := keys.Generate()
			if err != nil {
				t.Fatal(err)
			}
			if err := legacy.WritePair(legacyPrivatePath(home), legacyPublicPath(home)); err != nil {
				t.Fatal(err)
			}
			keyID, err := legacy.KeyID()
			if err != nil {
				t.Fatal(err)
			}
			recovery := filepath.Join(offline, "recovery.json")
			interrupted := false
			func() {
				defer func() {
					if recover() != nil {
						interrupted = true
					}
				}()
				migrationMutationBoundary = func(reached string) {
					if reached == boundary {
						panic(fmt.Sprintf("simulated process loss at %s", reached))
					}
				}
				defer func() { migrationMutationBoundary = nil }()
				_, _ = MigrateLegacy(home, recovery, []byte(testPassphrase), "migration test", keyID, LedgerBoundary{SequenceNo: -1})
			}()
			migrationMutationBoundary = nil
			if !interrupted {
				t.Fatalf("test did not reach migration boundary %s", boundary)
			}
			if pending, err := MigrationPending(home); err != nil || !pending {
				t.Fatalf("interruption did not preserve a migration journal: pending=%v err=%v", pending, err)
			}
			state, err := RecoverPendingMigration(home)
			early := boundary == "journal_durable" || boundary == "recovery_package_staged"
			if early {
				if !errors.Is(err, ErrMigrationRolledBack) {
					t.Fatalf("early interruption did not roll back safely: %v", err)
				}
				if state != nil || IsBPlus(home) || !fileExists(legacyPrivatePath(home)) {
					t.Fatal("early migration rollback changed the legacy signing authority")
				}
				if _, statErr := os.Lstat(recovery); !os.IsNotExist(statErr) {
					t.Fatalf("early rollback published a recovery package: %v", statErr)
				}
			} else {
				if err != nil {
					t.Fatalf("RecoverPendingMigration: %v", err)
				}
				if state == nil || !IsBPlus(home) || state.Active() == nil || state.Active().EpochNumber != 0 {
					t.Fatalf("recovery did not establish the migrated epoch-zero authority: %#v", state)
				}
				if _, statErr := os.Lstat(legacyPrivatePath(home)); !os.IsNotExist(statErr) {
					t.Fatalf("legacy private path remained active after migration: %v", statErr)
				}
				if _, verifyErr := VerifyRecoveryPackage(recovery, []byte(testPassphrase), state.Genesis.IdentityID); verifyErr != nil {
					t.Fatalf("published recovery package: %v", verifyErr)
				}
			}
			if pending, pendingErr := MigrationPending(home); pendingErr != nil || pending {
				t.Fatalf("recovery left a migration journal: pending=%v err=%v", pending, pendingErr)
			}
		})
	}
}

func TestPublishNewPathNeverReplacesExistingDestination(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishNewPath(source, destination); err == nil {
		t.Fatal("atomic no-replace publication replaced an existing destination")
	}
	raw, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "existing" {
		t.Fatalf("existing destination changed to %q", raw)
	}
}
