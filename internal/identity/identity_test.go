package identity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
)

const testPassphrase = "correct horse battery staple"

func initializeTestIdentity(t *testing.T) (string, string, *State) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "evidence")
	recovery := filepath.Join(root, "offline", "recovery.json")
	if err := os.Mkdir(filepath.Dir(recovery), 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := Initialize(home, recovery, []byte(testPassphrase), "test ledger")
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return home, recovery, state
}

func TestInitializeCreatesStableIdentityAndOfflineRecoveryOnly(t *testing.T) {
	home, recovery, state := initializeTestIdentity(t)
	if state.Genesis.IdentityID == state.Genesis.EpochZeroKeyID {
		t.Fatal("stable identity unexpectedly equals the operational key fingerprint")
	}
	if state.Active() == nil || state.Active().EpochNumber != 0 || state.Active().Status != StatusActive {
		t.Fatalf("unexpected active epoch: %#v", state.Active())
	}
	if _, err := VerifyRecoveryPackage(recovery, []byte(testPassphrase), state.Genesis.IdentityID); err != nil {
		t.Fatalf("VerifyRecoveryPackage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "recovery.json")); !os.IsNotExist(err) {
		t.Fatalf("recovery package was stored inside the evidence home: %v", err)
	}
	if err := filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(string(raw), "recovery_private_key_pem") {
				t.Fatalf("recovery private material appears in %s", path)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleTransitionsPreserveExactlyOneActiveEpoch(t *testing.T) {
	home, recovery, initial := initializeTestIdentity(t)
	identityID := initial.Genesis.IdentityID

	rotated, rotation, err := ApplyMutation(home, recovery, []byte(testPassphrase), MutationRequest{
		Action: ActionRotate, ReasonCode: "ROUTINE_DEVICE_TRANSFER", Boundary: LedgerBoundary{SequenceNo: -1},
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.Genesis.IdentityID != identityID || rotated.Active() == nil || rotated.Active().EpochNumber != 1 {
		t.Fatalf("rotation changed identity or failed to activate epoch 1: %#v", rotated.Active())
	}
	if rotated.Epochs[0].Status != StatusRetired || rotation.PreviousEpoch.OperationalStatus != StatusRetired {
		t.Fatalf("epoch zero was not retired: %#v", rotated.Epochs[0])
	}
	if _, err := os.Stat(epochPrivatePath(home, 0)); !os.IsNotExist(err) {
		t.Fatalf("retired private key remained in the live home: %v", err)
	}

	suspended, _, err := ApplyMutation(home, recovery, []byte(testPassphrase), MutationRequest{
		Action: ActionSuspend, ReasonCode: "OWNER_REQUESTED_SUSPENSION", Boundary: LedgerBoundary{SequenceNo: -1},
	})
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if suspended.Active() != nil || suspended.Epochs[1].Status != StatusSuspended {
		t.Fatalf("suspension left an active signer: %#v", suspended.Active())
	}
	if _, err := LoadSigning(home); err == nil {
		t.Fatal("suspended identity still admitted signing")
	}

	resumed, _, err := ApplyMutation(home, recovery, []byte(testPassphrase), MutationRequest{
		Action: ActionResume, ReasonCode: "OWNER_RESUMED_SIGNING", Boundary: LedgerBoundary{SequenceNo: -1},
	})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.Active() == nil || resumed.Active().EpochNumber != 1 || len(resumed.Epochs[1].Windows) != 2 {
		t.Fatalf("resumption did not reopen the suspended epoch: %#v", resumed.Epochs[1])
	}

	recovered, recoveryRecord, err := ApplyMutation(home, recovery, []byte(testPassphrase), MutationRequest{
		Action: ActionRecover, ReasonCode: "OPERATIONAL_KEY_LOST", Boundary: LedgerBoundary{SequenceNo: -1},
	})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered.Active() == nil || recovered.Active().EpochNumber != 2 || recovered.Epochs[1].Status != StatusRevoked {
		t.Fatalf("recovery did not revoke and replace epoch 1: %#v", recovered.Epochs)
	}
	if recoveryRecord.RetiringSignatureB64 != nil {
		t.Fatal("lost-key recovery unexpectedly required the missing key")
	}

	revoked, _, err := ApplyMutation(home, recovery, []byte(testPassphrase), MutationRequest{
		Action: ActionRevoke, ReasonCode: "CONFIRMED_COMPROMISE", Boundary: LedgerBoundary{SequenceNo: -1},
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Active() != nil || revoked.Epochs[2].Status != StatusRevoked {
		t.Fatalf("revocation left signing authority: %#v", revoked.Active())
	}
	if _, err := LoadSigning(home); err == nil {
		t.Fatal("revoked identity still admitted signing")
	}
}

func TestTransitionCannotBeAuthorizedWithoutRecoveryRoot(t *testing.T) {
	_, _, state := initializeTestIdentity(t)
	current := state.ActivePair
	proposed, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	attackerRoot, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewLifecycleRecord(state, attackerRoot, current, proposed, MutationRequest{
		Action: ActionRotate, ReasonCode: "ATTACKER_TRANSITION", Boundary: LedgerBoundary{SequenceNo: -1},
	})
	if err == nil || !strings.Contains(err.Error(), "does not control this identity") {
		t.Fatalf("old and new operational keys bypassed recovery-root authority: %v", err)
	}
}

func TestLifecycleTamperingAndForksFailClosed(t *testing.T) {
	home, recovery, _ := initializeTestIdentity(t)
	state, _, err := ApplyMutation(home, recovery, []byte(testPassphrase), MutationRequest{
		Action: ActionRotate, ReasonCode: "ROUTINE_ROTATION", Boundary: LedgerBoundary{SequenceNo: -1},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(state.Records)
	if err != nil {
		t.Fatal(err)
	}
	var records []*LifecycleRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		t.Fatal(err)
	}
	records[1].ReasonCode = "ALTERED_REASON"
	if _, err := DeriveState("", state.Genesis, records); err == nil {
		t.Fatal("tampered lifecycle record was accepted")
	}

	if _, err := DeriveState("", state.Genesis, state.Records[1:]); err == nil {
		t.Fatal("truncated lifecycle chain was accepted")
	}
	duplicated := append(append([]*LifecycleRecord{}, state.Records...), state.Records[1])
	if _, err := DeriveState("", state.Genesis, duplicated); err == nil {
		t.Fatal("duplicated lifecycle record was accepted")
	}
}

func TestCheckpointImportRejectsRollbackAndConflict(t *testing.T) {
	home, recovery, initial := initializeTestIdentity(t)
	initialCheckpoint, err := NewLifecycleCheckpoint(initial)
	if err != nil {
		t.Fatal(err)
	}
	initialRaw, _ := json.Marshal(initialCheckpoint)

	rotated, _, err := ApplyMutation(home, recovery, []byte(testPassphrase), MutationRequest{
		Action: ActionRotate, ReasonCode: "ROUTINE_ROTATION", Boundary: LedgerBoundary{SequenceNo: -1},
	})
	if err != nil {
		t.Fatal(err)
	}
	newCheckpoint, _ := NewLifecycleCheckpoint(rotated)
	newRaw, _ := json.Marshal(newCheckpoint)
	store := filepath.Join(t.TempDir(), "trust")
	if _, err := ImportCheckpoint(newRaw, store, rotated.Genesis.IdentityID); err != nil {
		t.Fatalf("import current checkpoint: %v", err)
	}
	if _, err := ImportCheckpoint(initialRaw, store, rotated.Genesis.IdentityID); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("checkpoint rollback was not rejected: %v", err)
	}

	root, _, err := OpenRecoveryPackage(recovery, []byte(testPassphrase), initial.Genesis.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(root.Private)
	alternatePair, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	alternateRecord, err := NewLifecycleRecord(initial, root, initial.ActivePair, alternatePair, MutationRequest{
		Action: ActionRotate, ReasonCode: "ALTERNATE_VALID_FORK", Boundary: LedgerBoundary{SequenceNo: -1},
	})
	if err != nil {
		t.Fatal(err)
	}
	alternateState, err := DeriveState("", initial.Genesis, []*LifecycleRecord{initial.Records[0], alternateRecord})
	if err != nil {
		t.Fatal(err)
	}
	conflict, err := NewLifecycleCheckpoint(alternateState)
	if err != nil {
		t.Fatal(err)
	}
	conflictRaw, _ := json.Marshal(conflict)
	if _, err := ImportCheckpoint(conflictRaw, store, rotated.Genesis.IdentityID); err == nil {
		t.Fatal("individually valid same-sequence checkpoint fork was accepted")
	}
}

func TestConcurrentCheckpointImportsRemainMonotonic(t *testing.T) {
	home, recovery, initial := initializeTestIdentity(t)
	states := []*State{initial}
	for range 4 {
		next, _, err := ApplyMutation(home, recovery, []byte(testPassphrase), MutationRequest{
			Action: ActionRotate, ReasonCode: "CONCURRENT_IMPORT", Boundary: LedgerBoundary{SequenceNo: -1},
		})
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, next)
	}
	raw := make([][]byte, len(states))
	for index, state := range states {
		checkpoint, err := NewLifecycleCheckpoint(state)
		if err != nil {
			t.Fatal(err)
		}
		raw[index], err = json.Marshal(checkpoint)
		if err != nil {
			t.Fatal(err)
		}
	}
	store := filepath.Join(t.TempDir(), "trust")
	start := make(chan struct{})
	errors := make(chan error, len(raw))
	for index := range raw {
		go func(index int) {
			<-start
			_, err := ImportCheckpoint(raw[index], store, initial.Genesis.IdentityID)
			if err != nil && !strings.Contains(err.Error(), "rollback") {
				errors <- err
				return
			}
			errors <- nil
		}(index)
	}
	close(start)
	for range raw {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	stored, _, err := LoadStoredCheckpoint(store, initial.Genesis.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CheckpointSequence != states[len(states)-1].LastSequence {
		t.Fatalf("stored checkpoint sequence %d, want %d", stored.CheckpointSequence, states[len(states)-1].LastSequence)
	}
}

func TestRecoveryPackageRejectsWrongPassphraseTamperingAndOversizeWithoutMutation(t *testing.T) {
	home, recovery, state := initializeTestIdentity(t)
	beforeHome := fileDigests(t, home)
	beforeRecovery, err := os.ReadFile(recovery)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecoveryPackage(recovery, []byte("wrong passphrase with enough bytes"), state.Genesis.IdentityID); err == nil {
		t.Fatal("recovery package accepted an incorrect passphrase")
	}

	var packageValue map[string]any
	if err := json.Unmarshal(beforeRecovery, &packageValue); err != nil {
		t.Fatal(err)
	}
	ciphertext := packageValue["ciphertext_b64"].(string)
	replacement := "A"
	if ciphertext[0] == 'A' {
		replacement = "B"
	}
	packageValue["ciphertext_b64"] = replacement + ciphertext[1:]
	tamperedRaw, err := json.Marshal(packageValue)
	if err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(filepath.Dir(recovery), "tampered.json")
	if err := os.WriteFile(tampered, tamperedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecoveryPackage(tampered, []byte(testPassphrase), state.Genesis.IdentityID); err == nil {
		t.Fatal("altered recovery package authenticated")
	}

	oversized := filepath.Join(filepath.Dir(recovery), "oversized.json")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(1024*1024 + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecoveryPackage(oversized, []byte(testPassphrase), state.Genesis.IdentityID); err == nil {
		t.Fatal("oversized recovery package was read")
	}
	if after := fileDigests(t, home); fmt.Sprint(beforeHome) != fmt.Sprint(after) {
		t.Fatalf("recovery-package failures changed the evidence home\nbefore=%v\nafter=%v", beforeHome, after)
	}
	afterRecovery, err := os.ReadFile(recovery)
	if err != nil || string(afterRecovery) != string(beforeRecovery) {
		t.Fatal("recovery-package verification changed the authoritative package")
	}
}

func fileDigests(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[relative] = fmt.Sprintf("%x", digest)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
