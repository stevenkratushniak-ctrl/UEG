package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// helper: create a minimal, internally-generated receipt (guarantees checksum + determinism_hash are consistent)
func makeEmptyReceiptForTest(t *testing.T) *Receipt {
	t.Helper()
	gw := NewGateway("test", false, false, true)
	r := gw.Process([]string{}) // empty input => stable logic, no external exec
	if r == nil {
		t.Fatalf("expected receipt, got nil")
	}
	if r.Checksum == "" || r.DeterminismHash == "" {
		t.Fatalf("expected checksum and determinism_hash to be set")
	}
	if !r.verifyChecksum() {
		t.Fatalf("expected receipt checksum to verify")
	}
	return r
}

func writeReceiptJSON(t *testing.T, dir string, r *Receipt) string {
	t.Helper()
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	p := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(p, b, 0644); err != nil {
		t.Fatalf("write receipt file: %v", err)
	}
	return p
}

func TestDeterminismHashStableAcrossExcludedFields(t *testing.T) {
	r := makeEmptyReceiptForTest(t)
	base := r.computeDeterminismHash()

	// mutate excluded fields: trace, timestamps, cwd, output text/duration
	r2 := *r
	r2.TraceID = "DIFFERENT"
	r2.StartTime = "2000-01-01T00:00:00Z"
	r2.EndTime = "2000-01-01T00:00:01Z"
	if r2.Meta != nil {
		r2.Meta.CWD = "/tmp/different"
	}
	if r2.FinalState != nil {
		r2.FinalState.TraceID = "DIFFERENT"
		r2.FinalState.Timestamp = "2000-01-01T00:00:00Z"
		if r2.FinalState.Output != nil {
			r2.FinalState.Output.Stdout = "noise"
			r2.FinalState.Output.Stderr = "noise"
			r2.FinalState.Output.DurationMs = 999999
		}
	}
	if got := r2.computeDeterminismHash(); got != base {
		t.Fatalf("determinism hash should ignore nondeterministic fields: got %q want %q", got, base)
	}
}

func TestDeterminismHashChangesOnDecisionPathChange(t *testing.T) {
	r := makeEmptyReceiptForTest(t)
	base := r.computeDeterminismHash()

	// Change something that should matter: final stage (decision outcome)
	r2 := *r
	r2.FinalStage = EXECUTED
	if got := r2.computeDeterminismHash(); got == base {
		t.Fatalf("determinism hash should change when decision outcome changes")
	}
}

func TestChecksumDetectsTamper(t *testing.T) {
	r := makeEmptyReceiptForTest(t)
	if !r.verifyChecksum() {
		t.Fatalf("expected checksum to verify")
	}
	// Tamper with a checksum-covered field (final_stage is covered)
	r.FinalStage = EXECUTED
	if r.verifyChecksum() {
		t.Fatalf("expected checksum verification to fail after tamper")
	}
}

func TestCapsuleZipDeterministicBytes(t *testing.T) {
	dir := t.TempDir()
	r := makeEmptyReceiptForTest(t)

	p1 := filepath.Join(dir, "capsule1.zip")
	p2 := filepath.Join(dir, "capsule2.zip")

	if err := writeCapsule(p1, r); err != nil {
		t.Fatalf("writeCapsule 1: %v", err)
	}
	if err := writeCapsule(p2, r); err != nil {
		t.Fatalf("writeCapsule 2: %v", err)
	}

	b1, err := os.ReadFile(p1)
	if err != nil {
		t.Fatalf("read capsule1: %v", err)
	}
	b2, err := os.ReadFile(p2)
	if err != nil {
		t.Fatalf("read capsule2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("capsule bytes must be identical across identical inputs (deterministic zip)")
	}
}

func TestReplayMatchEmptyInput(t *testing.T) {
	dir := t.TempDir()
	r := makeEmptyReceiptForTest(t)
	p := writeReceiptJSON(t, dir, r)

	_, ok, code := Replay(p, false, false, true)
	if !ok || code != "MATCH" {
		t.Fatalf("expected MATCH, got ok=%v code=%s", ok, code)
	}
}

func TestReplayTamperedDetected(t *testing.T) {
	dir := t.TempDir()
	r := makeEmptyReceiptForTest(t)
	p := writeReceiptJSON(t, dir, r)

	// Tamper with a checksum-covered field in the JSON on disk.
	var disk Receipt
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	disk.FinalStage = EXECUTED // checksum should fail now
	raw2, _ := json.MarshalIndent(&disk, "", "  ")
	if err := os.WriteFile(p, raw2, 0644); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	_, ok, code := Replay(p, false, false, true)
	if ok || code != "TAMPERED" {
		t.Fatalf("expected TAMPERED, got ok=%v code=%s", ok, code)
	}
}

func TestReplayDivergedDeterminismHash(t *testing.T) {
	dir := t.TempDir()
	r := makeEmptyReceiptForTest(t)
	p := writeReceiptJSON(t, dir, r)

	// Change determinism_hash only (checksum does not cover it), forcing DIVERGED.
	var disk Receipt
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	disk.DeterminismHash = "deadbeefdeadbeef"
	raw2, _ := json.MarshalIndent(&disk, "", "  ")
	if err := os.WriteFile(p, raw2, 0644); err != nil {
		t.Fatalf("write diverged: %v", err)
	}

	_, ok, code := Replay(p, false, false, true)
	if ok || code != "DIVERGED" {
		t.Fatalf("expected DIVERGED, got ok=%v code=%s", ok, code)
	}
}

func TestDeterminismHashHandlesSparseReceipt(t *testing.T) {
	r := &Receipt{
		Version:     "1.2.0",
		Input:       []string{"noop"},
		Transitions: []*Transition{nil},
	}

	if got := r.computeDeterminismHash(); got == "" {
		t.Fatalf("expected determinism hash for sparse receipt")
	}
}
