package ledger

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func newLedger(t *testing.T) *Ledger {
	t.Helper()
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return l
}

func TestIdentityCreatedIsReportedOnlyForFirstOpen(t *testing.T) {
	home := t.TempDir()
	first, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if !first.IdentityCreated {
		t.Fatal("first open did not report the newly created identity")
	}
	second, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if second.IdentityCreated {
		t.Fatal("reopening an existing identity reported a new identity")
	}
	if first.KeyID != second.KeyID {
		t.Fatal("reopening changed the signing identity")
	}
}

func appendOne(t *testing.T, l *Ledger, target string) *Receipt {
	t.Helper()
	p := Petition{"action": "execute", "surface": "fs.read", "target": target, "argv": []any{"echo", target}}
	r, err := l.Append(p, PetitionSummary{Surface: "fs.read", Action: "execute", Target: target},
		"ueg:test", "ADMITTED", "EXPRESSED", "0"+strings.Repeat("0", 63), []string{"read.only.inspect"})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	return r
}

func TestChainVerifies(t *testing.T) {
	l := newLedger(t)
	appendOne(t, l, "one")
	appendOne(t, l, "two")

	res := Verify(l.Receipts(), l.TrustSelf())
	if !res.OK {
		t.Fatalf("fresh chain did not verify: %v", res.Findings)
	}
	if res.Checked != 2 {
		t.Fatalf("checked %d receipts, want 2", res.Checked)
	}
	if bind := VerifyPetitions(l.Receipts(), l.Petitions()); !bind.OK {
		t.Fatalf("petitions did not bind: %v", bind.Findings)
	}
}

func TestChainLinksForward(t *testing.T) {
	l := newLedger(t)
	first := appendOne(t, l, "one")
	second := appendOne(t, l, "two")
	if first.PrevReceiptID != nil {
		t.Fatal("the first receipt must not name a predecessor")
	}
	if second.PrevReceiptID == nil || *second.PrevReceiptID != first.ReceiptID {
		t.Fatal("the second receipt does not link to the first")
	}
}

func TestReorderedReceiptFileIsDetectedAfterReopen(t *testing.T) {
	home := t.TempDir()
	l, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	appendOne(t, l, "one")
	appendOne(t, l, "two")

	data := mustReadFile(t, l.ReceiptsPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("fixture has %d receipt lines, want 2", len(lines))
	}
	reordered := lines[1] + "\n" + lines[0] + "\n"
	if err := os.WriteFile(l.ReceiptsPath, []byte(reordered), 0o644); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenReadOnly(home)
	if err != nil {
		t.Fatal(err)
	}
	if res := Verify(reopened.Receipts(), reopened.TrustSelf()); res.OK {
		t.Fatal("reordered receipt file was silently normalized and accepted")
	}
}

// Editing a recorded fact must be detected. This is the check the previous
// implementation computed a checksum for and then never performed.
func TestEditedReceiptIsDetected(t *testing.T) {
	l := newLedger(t)
	appendOne(t, l, "one")

	tampered := reload(t, l, func(receipts []map[string]any) {
		receipts[0]["petition_summary"].(map[string]any)["target"] = "echo something-else"
	})
	res := Verify(tampered, l.TrustSelf())
	if res.OK {
		t.Fatal("a receipt was edited and the chain still verified")
	}
	if !strings.Contains(strings.Join(res.Findings, " "), "do not match receipt_id") {
		t.Fatalf("wrong finding: %v", res.Findings)
	}
}

// Recomputing the id after editing does not help: the signature is over the id.
func TestEditedReceiptWithRecomputedIDIsDetected(t *testing.T) {
	l := newLedger(t)
	appendOne(t, l, "one")

	tampered := reload(t, l, func(receipts []map[string]any) {
		receipts[0]["admission_outcome"] = "REFUSED"
	})
	// Recompute the id the way an attacker would.
	fixed, err := tampered[0].ComputeID()
	if err != nil {
		t.Fatal(err)
	}
	tampered[0].ReceiptID = fixed

	res := Verify(tampered, l.TrustSelf())
	if res.OK {
		t.Fatal("an edited receipt with a recomputed id still verified")
	}
	if !strings.Contains(strings.Join(res.Findings, " "), "signature") {
		t.Fatalf("wrong finding: %v", res.Findings)
	}
}

func TestRemovedReceiptIsDetected(t *testing.T) {
	l := newLedger(t)
	appendOne(t, l, "one")
	appendOne(t, l, "two")
	appendOne(t, l, "three")

	all := l.Receipts()
	gapped := []*Receipt{all[0], all[2]}
	if res := Verify(gapped, l.TrustSelf()); res.OK {
		t.Fatal("a receipt was removed from the middle and the chain still verified")
	}
}

func TestForeignKeyIsRejected(t *testing.T) {
	l := newLedger(t)
	appendOne(t, l, "one")
	other := newLedger(t)
	if res := Verify(l.Receipts(), other.TrustSelf()); res.OK {
		t.Fatal("receipts verified against a key that did not sign them")
	}
}

// A field the schema does not define would be an unsigned place to hide data,
// because receipt_id is computed over a fixed field list.
func TestUnknownFieldIsRejected(t *testing.T) {
	l := newLedger(t)
	r := appendOne(t, l, "one")

	raw, err := marshalSorted(r)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["smuggled"] = "payload"
	line, _ := json.Marshal(obj)

	if _, err := ParseReceiptStrict(line); err == nil {
		t.Fatal("a receipt with an extra field was accepted")
	}
}

func TestDuplicateKeyIsRejected(t *testing.T) {
	line := []byte(`{"actor":"a","actor":"b"}`)
	if _, err := ParseReceiptStrict(line); err == nil {
		t.Fatal("duplicate keys were accepted")
	}
}

// Editing the stored request must be detected even though the request is not
// part of the Receipt v1 schema: petition_hash binds it.
func TestEditedPetitionIsDetected(t *testing.T) {
	l := newLedger(t)
	appendOne(t, l, "one")

	petitions := l.Petitions()
	petitions[0]["target"] = "echo something-else"
	if res := VerifyPetitions(l.Receipts(), petitions); res.OK {
		t.Fatal("the recorded request was edited and still bound to its receipt")
	}
}

func TestPetitionBindingIsBijective(t *testing.T) {
	l := newLedger(t)
	appendOne(t, l, "one")
	appendOne(t, l, "two")

	clone := func(source Petition) Petition {
		copy := Petition{}
		for key, value := range source {
			copy[key] = value
		}
		return copy
	}
	receipts := l.Receipts()
	petitions := l.Petitions()

	t.Run("extra petition", func(t *testing.T) {
		extra := append([]Petition{}, petitions...)
		extra = append(extra, clone(petitions[0]))
		if result := VerifyPetitions(receipts, extra); result.OK {
			t.Fatal("an extra petition was accepted")
		}
	})

	t.Run("duplicate receipt", func(t *testing.T) {
		duplicate := []Petition{clone(petitions[0]), clone(petitions[0])}
		if result := VerifyPetitions(receipts, duplicate); result.OK {
			t.Fatal("a duplicate petition for one receipt was accepted")
		}
	})

	t.Run("duplicate receipt id", func(t *testing.T) {
		duplicate := []Petition{clone(petitions[0]), clone(petitions[1])}
		duplicate[1]["receipt_id"] = duplicate[0]["receipt_id"]
		if result := VerifyPetitions(receipts, duplicate); result.OK {
			t.Fatal("duplicate petition receipt ids were accepted")
		}
	})

	t.Run("wrong receipt id", func(t *testing.T) {
		wrong := []Petition{clone(petitions[0]), clone(petitions[1])}
		wrong[0]["receipt_id"] = receipts[1].ReceiptID
		if result := VerifyPetitions(receipts, wrong); result.OK {
			t.Fatal("a petition bound to the wrong receipt id was accepted")
		}
	})
}

func TestRepeatedIdenticalPetitionsRemainValid(t *testing.T) {
	l := newLedger(t)
	appendOne(t, l, "same")
	appendOne(t, l, "same")
	if l.Receipts()[0].PetitionHash != l.Receipts()[1].PetitionHash {
		t.Fatal("test setup did not produce identical petition hashes")
	}
	if result := VerifyPetitions(l.Receipts(), l.Petitions()); !result.OK {
		t.Fatalf("identical requests with distinct receipts did not verify: %v", result.Findings)
	}
}

func TestPetitionsPersistAcrossOpen(t *testing.T) {
	home := t.TempDir()
	l, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	appendOne(t, l, "one")

	reopened, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Receipts()) != 1 || len(reopened.Petitions()) != 1 {
		t.Fatalf("reopened ledger has %d receipts and %d petitions", len(reopened.Receipts()), len(reopened.Petitions()))
	}
	if res := Verify(reopened.Receipts(), reopened.TrustSelf()); !res.OK {
		t.Fatalf("reopened chain did not verify: %v", res.Findings)
	}
	if res := VerifyPetitions(reopened.Receipts(), reopened.Petitions()); !res.OK {
		t.Fatalf("reopened petitions did not bind: %v", res.Findings)
	}
}

func TestReadOnlyOpenUsesNoPrivateKeyAndCreatesNothing(t *testing.T) {
	home := t.TempDir()
	l, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	appendOne(t, l, "one")

	readOnly, err := OpenReadOnly(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(readOnly.Pair.Private) != 0 {
		t.Fatal("read-only open loaded private key material")
	}
	if len(readOnly.Receipts()) != 1 {
		t.Fatalf("read-only open loaded %d receipts, want 1", len(readOnly.Receipts()))
	}

	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := OpenReadOnly(missing); err == nil {
		t.Fatal("read-only open accepted a missing evidence home")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("read-only open created or changed the missing home: %v", err)
	}
}

func TestInterruptedPairRecoversBeforeNextWrite(t *testing.T) {
	home := t.TempDir()
	l, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	realPetitionsPath := l.PetitionsPath
	blockedPath := filepath.Join(home, "blocked-petitions")
	if err := os.Mkdir(blockedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	l.PetitionsPath = blockedPath
	p := Petition{"action": "execute", "surface": "fs.read", "target": "interrupted", "argv": []any{"echo", "interrupted"}}
	_, err = l.Append(p, PetitionSummary{Surface: "fs.read", Action: "execute", Target: "interrupted"},
		"ueg:test", "ADMITTED", "SILENT", "0"+strings.Repeat("0", 63), []string{"read.only.inspect"})
	if err == nil {
		t.Fatal("fixture did not interrupt the petition write")
	}
	pending, err := RecoveryPending(home)
	if err != nil {
		t.Fatal(err)
	}
	if !pending {
		t.Fatal("the interrupted pair did not leave a recovery record")
	}
	l.PetitionsPath = realPetitionsPath

	if _, err := OpenExisting(home); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("write-capable open returned %v, want ErrRecoveryRequired", err)
	}
	recovered, err := RecoverExisting(home)
	if err != nil {
		t.Fatalf("recover pending pair: %v", err)
	}
	pending, err = RecoveryPending(home)
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("recovery record remained after recovery")
	}
	if len(recovered.Receipts()) != 1 || len(recovered.Petitions()) != 1 {
		t.Fatalf("recovered %d receipts and %d petitions", len(recovered.Receipts()), len(recovered.Petitions()))
	}
	if chain := Verify(recovered.Receipts(), recovered.TrustSelf()); !chain.OK {
		t.Fatalf("recovered chain: %v", chain.Findings)
	}
	if bind := VerifyPetitions(recovered.Receipts(), recovered.Petitions()); !bind.OK {
		t.Fatalf("recovered petitions: %v", bind.Findings)
	}
}

func TestInvalidRecoveryPlanDoesNotMutateEvidence(t *testing.T) {
	home := t.TempDir()
	l, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	appendOne(t, l, "existing")

	realReceiptsPath := l.ReceiptsPath
	blockedPath := filepath.Join(home, "blocked-receipts")
	if err := os.Mkdir(blockedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	l.ReceiptsPath = blockedPath
	p := Petition{"action": "execute", "surface": "fs.read", "target": "pending", "argv": []any{"echo", "pending"}}
	_, err = l.Append(p, PetitionSummary{Surface: "fs.read", Action: "execute", Target: "pending"},
		"ueg:test", "ADMITTED", "SILENT", "0"+strings.Repeat("0", 63), []string{"read.only.inspect"})
	if err == nil {
		t.Fatal("fixture did not interrupt the receipt write")
	}
	l.ReceiptsPath = realReceiptsPath
	if err := os.WriteFile(l.PetitionsPath, append(mustReadFile(t, l.PetitionsPath), []byte("synthetic-invalid-line\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	paths := []string{l.ReceiptsPath, l.PetitionsPath, filepath.Join(home, pendingName)}
	before := map[string]string{}
	for _, path := range paths {
		before[path] = string(mustReadFile(t, path))
	}
	if _, err := Open(home); err == nil {
		t.Fatal("invalid companion evidence unexpectedly recovered")
	}
	for _, path := range paths {
		if after := string(mustReadFile(t, path)); after != before[path] {
			t.Fatalf("failed recovery modified %s", filepath.Base(path))
		}
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAppendRefusesToExtendMissingPetition(t *testing.T) {
	l := newLedger(t)
	appendOne(t, l, "one")
	l.petitions = nil
	if _, err := l.Append(Petition{"action": "execute", "surface": "fs.read", "target": "two"},
		PetitionSummary{Surface: "fs.read", Action: "execute", Target: "two"},
		"ueg:test", "ADMITTED", "SILENT", "0"+strings.Repeat("0", 63), nil); err == nil {
		t.Fatal("append extended evidence with a missing petition")
	}
}

func TestPrivateKeyIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose ACL secrecy through os.FileMode permission bits")
	}
	home := t.TempDir()
	if _, err := Open(home); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(home, "keys", "ed25519_private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("private key mode is %o; it must not be readable by other users", mode)
	}
}

// reload round-trips the receipts through JSON so a mutation is applied the way
// an editor on disk would apply it.
func reload(t *testing.T, l *Ledger, mutate func([]map[string]any)) []*Receipt {
	t.Helper()
	objs := make([]map[string]any, 0, len(l.Receipts()))
	for _, r := range l.Receipts() {
		raw, err := marshalSorted(r)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatal(err)
		}
		objs = append(objs, obj)
	}
	mutate(objs)

	out := make([]*Receipt, 0, len(objs))
	for _, obj := range objs {
		line, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseReceiptStrict(line)
		if err != nil {
			t.Fatalf("tampered receipt did not parse: %v", err)
		}
		out = append(out, r)
	}
	return out
}
