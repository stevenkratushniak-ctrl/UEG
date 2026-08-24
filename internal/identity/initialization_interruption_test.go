package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializationRecoversAtEveryDurableMutationBoundary(t *testing.T) {
	boundaries := []string{
		"journal_durable",
		"recovery_package_self_tested",
		"authority_staged",
		"recovery_package_published",
		"home_published",
		"before_cleanup",
	}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "evidence")
			offline := filepath.Join(root, "offline")
			if err := os.Mkdir(offline, 0o700); err != nil {
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
				initializationMutationBoundary = func(reached string) {
					if reached == boundary {
						panic(fmt.Sprintf("simulated process loss at %s", reached))
					}
				}
				defer func() { initializationMutationBoundary = nil }()
				_, _ = Initialize(home, recovery, []byte(testPassphrase), "initialization test")
			}()
			initializationMutationBoundary = nil
			if !interrupted {
				t.Fatalf("test did not reach initialization boundary %s", boundary)
			}
			if pending, err := InitializationPending(home); err != nil || !pending {
				t.Fatalf("interruption did not preserve an initialization journal: pending=%v err=%v", pending, err)
			}
			state, err := RecoverPendingInitialization(home, []byte(testPassphrase))
			early := boundary == "journal_durable" || boundary == "recovery_package_self_tested"
			if early {
				if !errors.Is(err, ErrInitializationRolledBack) {
					t.Fatalf("early initialization did not roll back safely: %v", err)
				}
				if state != nil || IsBPlus(home) {
					t.Fatal("early initialization rollback created an evidence identity")
				}
				if _, statErr := os.Lstat(recovery); !os.IsNotExist(statErr) {
					t.Fatalf("early rollback published a recovery package: %v", statErr)
				}
			} else {
				if err != nil {
					t.Fatalf("RecoverPendingInitialization: %v", err)
				}
				if state == nil || state.Active() == nil || state.Active().EpochNumber != 0 || !IsBPlus(home) {
					t.Fatalf("recovery did not establish exactly one genesis epoch: %#v", state)
				}
				if _, verifyErr := VerifyRecoveryPackage(recovery, []byte(testPassphrase), state.Genesis.IdentityID); verifyErr != nil {
					t.Fatalf("published recovery package: %v", verifyErr)
				}
			}
			if pending, pendingErr := InitializationPending(home); pendingErr != nil || pending {
				t.Fatalf("recovery left an initialization journal: pending=%v err=%v", pending, pendingErr)
			}
		})
	}
}

func TestInitializationNeverOverwritesRecoveryPackageOrHome(t *testing.T) {
	root := t.TempDir()
	offline := filepath.Join(root, "offline")
	if err := os.Mkdir(offline, 0o700); err != nil {
		t.Fatal(err)
	}
	recovery := filepath.Join(offline, "recovery.json")
	if err := os.WriteFile(recovery, []byte("owner data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(filepath.Join(root, "evidence"), recovery, []byte(testPassphrase), ""); err == nil {
		t.Fatal("initialization accepted an existing recovery-package destination")
	}
	raw, err := os.ReadFile(recovery)
	if err != nil || string(raw) != "owner data" {
		t.Fatalf("existing recovery destination changed: %q %v", raw, err)
	}

	home := filepath.Join(root, "existing-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "owner.txt")
	if err := os.WriteFile(marker, []byte("owner data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(home, filepath.Join(offline, "second.json"), []byte(testPassphrase), ""); err == nil {
		t.Fatal("initialization accepted an existing evidence-home destination")
	}
	raw, err = os.ReadFile(marker)
	if err != nil || string(raw) != "owner data" {
		t.Fatalf("existing evidence home changed: %q %v", raw, err)
	}
}
