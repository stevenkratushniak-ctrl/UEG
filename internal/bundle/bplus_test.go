package bundle

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stevenkratushniak-ctrl/ueg/internal/identity"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
)

const bPlusTestPassphrase = "test-only B+ recovery passphrase"

func newBPlusLedger(t *testing.T) (string, string, *ledger.Ledger) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "evidence")
	offline := filepath.Join(root, "offline")
	if err := os.Mkdir(offline, 0o700); err != nil {
		t.Fatal(err)
	}
	recovery := filepath.Join(offline, "recovery.json")
	if _, err := identity.Initialize(home, recovery, []byte(bPlusTestPassphrase), "bundle qualification"); err != nil {
		t.Fatal(err)
	}
	l, err := ledger.OpenExisting(home)
	if err != nil {
		t.Fatal(err)
	}
	appendSyntheticReceipt(t, l, "epoch-zero")
	return home, recovery, l
}

func appendSyntheticReceipt(t *testing.T, l *ledger.Ledger, target string) {
	t.Helper()
	_, err := l.Append(
		ledger.Petition{"action": "qualification", "surface": "test", "target": target},
		ledger.PetitionSummary{Surface: "test", Action: "qualification", Target: target},
		"ueg:test", "ADMITTED", "SILENT", strings.Repeat("a", 64), []string{"qualification"},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func writeCheckpoint(t *testing.T, state *identity.State, path string) {
	t.Helper()
	checkpoint, err := identity.NewLifecycleCheckpoint(state)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeAnchor(t *testing.T, anchor *identity.EvidenceAnchor, path string) {
	t.Helper()
	raw, err := json.MarshalIndent(anchor, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		if _, err := io.Copy(output, input); err != nil {
			_ = output.Close()
			return err
		}
		return output.Close()
	}); err != nil {
		t.Fatal(err)
	}
	if err := copyTreeSecurityMetadata(source, destination); err != nil {
		t.Fatal(err)
	}
}

func TestBPlusBundleRequiresIndependentIdentityAndCheckpoint(t *testing.T) {
	_, _, l := newBPlusLedger(t)
	bundlePath := filepath.Join(t.TempDir(), "bplus.tar.gz")
	if err := Build(l, bundlePath); err != nil {
		t.Fatal(err)
	}
	unpinned := Verify(bundlePath)
	if !unpinned.OK || unpinned.OverallTrust != OverallIndeterminate || unpinned.ReasonCode != "MISSING_EXTERNAL_IDENTITY_PIN" {
		t.Fatalf("self-contained B+ bundle received the wrong trust result: %+v", unpinned)
	}
	checkpointPath := filepath.Join(t.TempDir(), "checkpoint.json")
	writeCheckpoint(t, l.IdentityState, checkpointPath)
	verified := VerifyWithOptions(bundlePath, Options{
		ExpectedIdentityID: l.IdentityID, ExternalCheckpointPath: checkpointPath,
	})
	if !verified.OK || verified.OverallTrust != OverallVerified || verified.ReasonCode != "BPLUS_VERIFIED_AT_CHECKPOINT" {
		t.Fatalf("independently pinned B+ bundle did not verify: %+v", verified)
	}
	current := VerifyWithOptions(bundlePath, Options{
		ExpectedIdentityID: l.IdentityID, ExternalCheckpointPath: checkpointPath, RequireCurrentStatus: true,
	})
	if !current.OK || current.OverallTrust != OverallIndeterminate || current.ReasonCode != "CURRENT_STATUS_FRESHNESS_UNAVAILABLE" {
		t.Fatalf("offline verifier falsely claimed current-status freshness: %+v", current)
	}
}

func TestBPlusRotationAuthorizesHistoricalAndNewEpochReceipts(t *testing.T) {
	home, recovery, first := newBPlusLedger(t)
	oldCheckpoint := filepath.Join(t.TempDir(), "old-checkpoint.json")
	writeCheckpoint(t, first.IdentityState, oldCheckpoint)
	if _, _, err := identity.ApplyMutation(home, recovery, []byte(bPlusTestPassphrase), identity.MutationRequest{
		Action: identity.ActionRotate, ReasonCode: "ROUTINE_ROTATION", Boundary: first.Boundary(),
	}); err != nil {
		t.Fatal(err)
	}
	rotated, err := ledger.OpenExisting(home)
	if err != nil {
		t.Fatal(err)
	}
	appendSyntheticReceipt(t, rotated, "epoch-one")
	bundlePath := filepath.Join(t.TempDir(), "rotated.tar.gz")
	if err := Build(rotated, bundlePath); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(t.TempDir(), "rotated-checkpoint.json")
	writeCheckpoint(t, rotated.IdentityState, checkpoint)
	verified := VerifyWithOptions(bundlePath, Options{ExpectedIdentityID: rotated.IdentityID, ExternalCheckpointPath: checkpoint})
	if verified.OverallTrust != OverallVerified || len(verified.SigningKeyIDs) != 2 {
		t.Fatalf("cross-epoch evidence did not verify: %+v", verified)
	}
	stale := VerifyWithOptions(bundlePath, Options{ExpectedIdentityID: rotated.IdentityID, ExternalCheckpointPath: oldCheckpoint})
	if stale.OverallTrust != OverallNotTrusted || stale.ReasonCode != "CHECKPOINT_ROLLBACK" {
		t.Fatalf("stale lifecycle checkpoint was not rejected: %+v", stale)
	}
}

func TestExternalCheckpointCannotAuthorizeAnotherReceiptFork(t *testing.T) {
	home, recovery, bundleLedger := newBPlusLedger(t)
	forkHome := filepath.Join(t.TempDir(), "fork")
	copyTree(t, home, forkHome)

	appendSyntheticReceipt(t, bundleLedger, "bundle-branch")
	bundlePath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := Build(bundleLedger, bundlePath); err != nil {
		t.Fatal(err)
	}

	forkLedger, err := ledger.OpenExisting(forkHome)
	if err != nil {
		t.Fatal(err)
	}
	appendSyntheticReceipt(t, forkLedger, "checkpoint-branch")
	forkState, _, err := identity.ApplyMutation(forkHome, recovery, []byte(bPlusTestPassphrase), identity.MutationRequest{
		Action: identity.ActionRotate, ReasonCode: "FORK_BOUNDARY_TEST", Boundary: forkLedger.Boundary(),
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(t.TempDir(), "fork-checkpoint.json")
	writeCheckpoint(t, forkState, checkpointPath)

	result := VerifyWithOptions(bundlePath, Options{
		ExpectedIdentityID: bundleLedger.IdentityID, ExternalCheckpointPath: checkpointPath,
	})
	if result.OverallTrust != OverallNotTrusted || result.ReasonCode != "CHECKPOINT_RECEIPT_BOUNDARY_MISMATCH" {
		t.Fatalf("checkpoint from another receipt fork was not rejected: %+v", result)
	}
}

func TestBPlusLifecycleTamperFailsEvenWithRepairedEnvelope(t *testing.T) {
	_, _, l := newBPlusLedger(t)
	bundlePath := filepath.Join(t.TempDir(), "original.tar.gz")
	if err := Build(l, bundlePath); err != nil {
		t.Fatal(err)
	}
	members := mustRead(t, bundlePath)
	members["identity/lifecycle.ndjson"] = []byte(strings.Replace(
		string(members["identity/lifecycle.ndjson"]), "IDENTITY_INITIALIZED", "ALTERED_REASON", 1,
	))
	resignChangedMembers(t, members, l)
	tampered := filepath.Join(t.TempDir(), "tampered.tar.gz")
	if err := writeTarGz(tampered, members); err != nil {
		t.Fatal(err)
	}
	result := Verify(tampered)
	if result.OK || result.OverallTrust != OverallInvalid {
		t.Fatalf("altered lifecycle passed a repaired bundle envelope: %+v", result)
	}
}

func TestRevokedEpochNeedsRootBoundIndependentAnchor(t *testing.T) {
	home, recovery, l := newBPlusLedger(t)
	bundlePath := filepath.Join(t.TempDir(), "pre-compromise.tar.gz")
	if err := Build(l, bundlePath); err != nil {
		t.Fatal(err)
	}
	anchor, err := identity.NewEvidenceAnchor(l.IdentityState, l.Boundary(), l.IdentityState.ActivePair)
	if err != nil {
		t.Fatal(err)
	}
	anchorPath := filepath.Join(t.TempDir(), "known-good-anchor.json")
	writeAnchor(t, anchor, anchorPath)
	digest := anchor.AnchorDigest
	revoked, _, err := identity.ApplyMutation(home, recovery, []byte(bPlusTestPassphrase), identity.MutationRequest{
		Action: identity.ActionRevoke, ReasonCode: "CONFIRMED_COMPROMISE", Boundary: l.Boundary(),
		EvidenceAnchorDigest: &digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	revokedCheckpoint := filepath.Join(t.TempDir(), "revoked-checkpoint.json")
	writeCheckpoint(t, revoked, revokedCheckpoint)
	withoutAnchor := VerifyWithOptions(bundlePath, Options{
		ExpectedIdentityID: l.IdentityID, ExternalCheckpointPath: revokedCheckpoint,
	})
	if withoutAnchor.OverallTrust != OverallIndeterminate || withoutAnchor.ReasonCode != "EPOCH_TRUST_INDETERMINATE" {
		t.Fatalf("revoked epoch without independent anchor received trust: %+v", withoutAnchor)
	}
	withAnchor := VerifyWithOptions(bundlePath, Options{
		ExpectedIdentityID: l.IdentityID, ExternalCheckpointPath: revokedCheckpoint, ExternalAnchorPath: anchorPath,
	})
	if withAnchor.OverallTrust != OverallVerified || withAnchor.EvidenceAnchor != "INDEPENDENT_MATCH" {
		t.Fatalf("root-bound independently retained pre-compromise anchor was not honored: %+v", withAnchor)
	}
}
