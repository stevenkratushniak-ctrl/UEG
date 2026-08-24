package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
)

func buildBundle(t *testing.T) (string, *ledger.Ledger) {
	t.Helper()
	l, err := ledger.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"one", "two", "three"} {
		p := ledger.Petition{"action": "execute", "surface": "fs.read", "target": target}
		if _, err := l.Append(p, ledger.PetitionSummary{Surface: "fs.read", Action: "execute", Target: target},
			"ueg:test", "ADMITTED", "EXPRESSED", strings.Repeat("0", 64), []string{"read.only.inspect"}); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "evidence.tar.gz")
	if err := Build(l, out); err != nil {
		t.Fatal(err)
	}
	return out, l
}

func TestBundleVerifies(t *testing.T) {
	path, l := buildBundle(t)
	res := Verify(path)
	if !res.OK {
		t.Fatalf("a freshly built bundle did not verify: %s", res.Reason)
	}
	if res.ReceiptCount != 3 {
		t.Fatalf("receipt count %d, want 3", res.ReceiptCount)
	}
	if res.TrustVerdict != TrustInternallyConsistent {
		t.Fatalf("unanchored bundle verdict %s, want %s", res.TrustVerdict, TrustInternallyConsistent)
	}
	expected, err := l.Pair.KeyID()
	if err != nil {
		t.Fatal(err)
	}
	trusted := VerifyWithOptions(path, Options{ExpectedKeyID: expected})
	if !trusted.OK || trusted.TrustVerdict != TrustIdentityTrusted {
		t.Fatalf("matching external pin did not establish identity trust: %+v", trusted)
	}
	mismatch := VerifyWithOptions(path, Options{ExpectedKeyID: "ueg:sha256:" + strings.Repeat("0", 64)})
	if mismatch.OK || mismatch.TrustVerdict != TrustIdentityMismatch {
		t.Fatalf("wrong external pin did not fail identity trust: %+v", mismatch)
	}
	if mismatch.ReceiptCount != 3 || len(mismatch.Checks) < 6 {
		t.Fatalf("identity mismatch discarded completed integrity evidence: %+v", mismatch)
	}
}

func TestNewBundleUsesFullKeyIdentityContract(t *testing.T) {
	path, l := buildBundle(t)
	members := mustRead(t, path)
	var manifest manifestDocument
	if err := json.Unmarshal(members["MANIFEST.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "v2" {
		t.Fatalf("new bundle manifest version %s, want v2", manifest.Version)
	}
	if !strings.HasPrefix(l.KeyID, "ueg:sha256:") || len(l.KeyID) != len("ueg:sha256:")+64 {
		t.Fatalf("new ledger uses incomplete key id %q", l.KeyID)
	}
}

func TestArchiveMemberNamesArePortable(t *testing.T) {
	valid := []string{"MANIFEST.json", "identity/lifecycle.ndjson", "a-b_c.1"}
	for _, name := range valid {
		if !safeName(name) {
			t.Errorf("portable member name %q was rejected", name)
		}
	}
	invalid := []string{
		"", "/absolute", `\absolute`, "../escape", "folder/../escape", "folder/./file",
		"folder//file", `folder\file`, "C:/drive", "identity/lifecycle?.json", "trailing/",
	}
	for _, name := range invalid {
		if safeName(name) {
			t.Errorf("nonportable member name %q was accepted", name)
		}
	}
}

func TestDuplicateManifestFieldIsRejectedBeforeVerification(t *testing.T) {
	path, l := buildBundle(t)
	members := mustRead(t, path)
	manifest := string(members["MANIFEST.json"])
	members["MANIFEST.json"] = []byte(strings.Replace(manifest, "{", `{"version":"v2",`, 1))
	seal, err := bundleSealBytes(members, l.KeyID, l.Pair)
	if err != nil {
		t.Fatal(err)
	}
	members["BUNDLE_SEAL.json"] = seal
	out := filepath.Join(t.TempDir(), "duplicate-manifest.tar.gz")
	if err := writeTarGz(out, members); err != nil {
		t.Fatal(err)
	}
	res := Verify(out)
	if res.OK || !strings.Contains(res.Reason, "duplicate JSON key") {
		t.Fatalf("duplicate field was not rejected strictly: %+v", res)
	}
}

func TestRevokedSigningKeyAndMalformedRevocationsAreRejected(t *testing.T) {
	path, l := buildBundle(t)

	t.Run("active signer revoked", func(t *testing.T) {
		members := mustRead(t, path)
		members["revocations.json"] = []byte(fmt.Sprintf(
			`[{"key_id":%q,"reason":"test","revoked_at":"2026-08-18T00:00:00Z"}]`, l.KeyID,
		))
		resignChangedMembers(t, members, l)
		out := filepath.Join(t.TempDir(), "revoked.tar.gz")
		if err := writeTarGz(out, members); err != nil {
			t.Fatal(err)
		}
		res := Verify(out)
		if res.OK || !strings.Contains(res.Reason, "every trust root is revoked") {
			t.Fatalf("revoked signer was not rejected: %+v", res)
		}
	})

	t.Run("malformed record", func(t *testing.T) {
		members := mustRead(t, path)
		members["revocations.json"] = []byte(`[{"key_id":42}]`)
		resignChangedMembers(t, members, l)
		out := filepath.Join(t.TempDir(), "malformed-revocation.tar.gz")
		if err := writeTarGz(out, members); err != nil {
			t.Fatal(err)
		}
		res := Verify(out)
		if res.OK || !strings.Contains(res.Reason, "invalid revocations.json") {
			t.Fatalf("malformed revocation was not rejected: %+v", res)
		}
	})
}

func TestTrustRootLabelMustMatchPublicKeyFingerprint(t *testing.T) {
	path, l := buildBundle(t)
	members := mustRead(t, path)
	var trust trustRootsDocument
	if err := json.Unmarshal(members["trust_roots.json"], &trust); err != nil {
		t.Fatal(err)
	}
	pemText := trust.Keys[l.KeyID]
	trust.Keys = map[string]string{"ueg:sha256:" + strings.Repeat("0", 64): pemText}
	members["trust_roots.json"], _ = json.MarshalIndent(trust, "", "  ")
	resignChangedMembers(t, members, l)
	out := filepath.Join(t.TempDir(), "relabeled-key.tar.gz")
	if err := writeTarGz(out, members); err != nil {
		t.Fatal(err)
	}
	res := Verify(out)
	if res.OK || !strings.Contains(res.Reason, "does not match the public-key fingerprint") {
		t.Fatalf("relabeled trust root was not rejected: %+v", res)
	}
}

func TestBundleIsByteIdenticalForTheSameEvidence(t *testing.T) {
	// The archive metadata is fixed, so only the two timestamps inside the
	// seals may differ between two exports of the same ledger.
	path, l := buildBundle(t)
	second := filepath.Join(t.TempDir(), "again.tar.gz")
	if err := Build(l, second); err != nil {
		t.Fatal(err)
	}
	a := mustRead(t, path)
	b := mustRead(t, second)
	if len(a) != len(b) {
		t.Fatalf("member counts differ: %d vs %d", len(a), len(b))
	}
	if string(a["receipts.ndjson"]) != string(b["receipts.ndjson"]) {
		t.Fatal("the same evidence produced different receipt bytes")
	}
	if string(a["trust_roots.json"]) != string(b["trust_roots.json"]) {
		t.Fatal("the same key produced different trust roots")
	}
}

func TestPrivateKeyIsNeverBundled(t *testing.T) {
	path, _ := buildBundle(t)
	for name, data := range mustRead(t, path) {
		if strings.Contains(name, "private") {
			t.Fatalf("the bundle holds %s", name)
		}
		if strings.Contains(string(data), "PRIVATE KEY") {
			t.Fatalf("%s holds private key material", name)
		}
	}
}

func TestEditedReceiptInBundleIsDetected(t *testing.T) {
	path, _ := buildBundle(t)
	members := mustRead(t, path)
	members["receipts.ndjson"] = []byte(strings.Replace(string(members["receipts.ndjson"]), `"target":"one"`, `"target":"xxx"`, 1))

	out := filepath.Join(t.TempDir(), "tampered.tar.gz")
	if err := writeTarGz(out, members); err != nil {
		t.Fatal(err)
	}
	res := Verify(out)
	if res.OK {
		t.Fatal("an edited receipt file verified")
	}
	if !strings.Contains(res.Reason, "hash mismatch") {
		t.Fatalf("unexpected reason: %s", res.Reason)
	}
}

// Rewriting the manifest to match the edit is the obvious next move; the
// bundle seal is what stops it.
func TestEditedReceiptWithRepairedManifestIsDetected(t *testing.T) {
	path, _ := buildBundle(t)
	members := mustRead(t, path)
	members["receipts.ndjson"] = []byte(strings.Replace(string(members["receipts.ndjson"]), `"target":"one"`, `"target":"xxx"`, 1))

	var manifest map[string]any
	if err := json.Unmarshal(members["MANIFEST.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["files"].(map[string]any)["receipts.ndjson"] = canon.SHA256Hex(members["receipts.ndjson"])
	repaired, _ := json.MarshalIndent(manifest, "", "  ")
	members["MANIFEST.json"] = repaired

	out := filepath.Join(t.TempDir(), "tampered.tar.gz")
	if err := writeTarGz(out, members); err != nil {
		t.Fatal(err)
	}
	res := Verify(out)
	if res.OK {
		t.Fatal("an edited receipt with a repaired manifest verified")
	}
	if !strings.Contains(res.Reason, "bundle seal") {
		t.Fatalf("unexpected reason: %s", res.Reason)
	}
}

func TestExtraFileIsDetected(t *testing.T) {
	path, _ := buildBundle(t)
	members := mustRead(t, path)
	members["extra.txt"] = []byte("smuggled")

	out := filepath.Join(t.TempDir(), "extra.tar.gz")
	if err := writeTarGz(out, members); err != nil {
		t.Fatal(err)
	}
	if res := Verify(out); res.OK {
		t.Fatal("a bundle with an unlisted file verified")
	}
}

func TestRemovedReceiptIsDetected(t *testing.T) {
	path, _ := buildBundle(t)
	members := mustRead(t, path)
	lines := strings.Split(strings.TrimSpace(string(members["receipts.ndjson"])), "\n")
	members["receipts.ndjson"] = []byte(strings.Join(lines[:2], "\n") + "\n")

	out := filepath.Join(t.TempDir(), "short.tar.gz")
	if err := writeTarGz(out, members); err != nil {
		t.Fatal(err)
	}
	if res := Verify(out); res.OK {
		t.Fatal("a bundle missing its last receipt verified")
	}
}

func TestRefusesToExportAnUnverifiableLedger(t *testing.T) {
	l, err := ledger.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := Build(l, filepath.Join(t.TempDir(), "empty.tar.gz")); err == nil {
		t.Fatal("an empty ledger was exported")
	}
}

func TestBuildDoesNotReplaceExistingDestination(t *testing.T) {
	_, l := buildBundle(t)
	destination := filepath.Join(t.TempDir(), "customer-notes.txt")
	original := []byte("keep this synthetic customer file")
	if err := os.WriteFile(destination, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Build(l, destination); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("existing destination returned %v, want ErrDestinationExists", err)
	}
	after, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("existing destination was modified")
	}
}

func TestBuildDoesNotTargetActiveEvidence(t *testing.T) {
	_, l := buildBundle(t)
	before, err := os.ReadFile(l.ReceiptsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := Build(l, l.ReceiptsPath); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("active receipt destination returned %v, want ErrDestinationExists", err)
	}
	after, err := os.ReadFile(l.ReceiptsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("active receipt file was modified")
	}
}

func TestBuildRejectsAlteredPetitionBeforeCreatingOutput(t *testing.T) {
	_, l := buildBundle(t)
	data, err := os.ReadFile(l.PetitionsPath)
	if err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(string(data), `"target":"one"`, `"target":"synthetic-alteration"`, 1)
	if altered == string(data) {
		t.Fatal("test setup did not alter a petition")
	}
	if err := os.WriteFile(l.PetitionsPath, []byte(altered), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "must-not-exist.tar.gz")
	if err := Build(l, destination); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("altered petition returned %v, want ErrEvidenceInvalid", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("invalid evidence left an export destination: %v", err)
	}
}

func TestBuildPublishesVerifiedBundleWithoutTemporaryResidue(t *testing.T) {
	_, l := buildBundle(t)
	directory := t.TempDir()
	destination := filepath.Join(directory, "published.tar.gz")
	if err := Build(l, destination); err != nil {
		t.Fatal(err)
	}
	if result := Verify(destination); !result.OK {
		t.Fatalf("published bundle did not verify: %s", result.Reason)
	}
	partials, err := filepath.Glob(filepath.Join(directory, ".published.tar.gz.ueg-export-*.partial"))
	if err != nil {
		t.Fatal(err)
	}
	if len(partials) != 0 {
		t.Fatalf("successful export left temporary files: %v", partials)
	}
}

func TestPublishNoReplacePreservesRaceWinner(t *testing.T) {
	directory := t.TempDir()
	tempPath := filepath.Join(directory, "complete.partial")
	destination := filepath.Join(directory, "winner.tar.gz")
	if err := os.WriteFile(tempPath, []byte("complete synthetic bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("race winner"), 0o600); err != nil {
		t.Fatal(err)
	}
	published, err := publishNoReplace(tempPath, destination)
	if err == nil || published {
		t.Fatalf("publish replaced a race winner: published=%v err=%v", published, err)
	}
	after, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "race winner" {
		t.Fatal("race winner destination was modified")
	}
}

func mustRead(t *testing.T, path string) map[string][]byte {
	t.Helper()
	members, err := readTarGz(path)
	if err != nil {
		t.Fatal(err)
	}
	return members
}

func resignChangedMembers(t *testing.T, members map[string][]byte, l *ledger.Ledger) {
	t.Helper()
	var manifest manifestDocument
	if err := json.Unmarshal(members["MANIFEST.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	for name := range manifest.Files {
		manifest.Files[name] = canon.SHA256Hex(members[name])
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	members["MANIFEST.json"] = manifestBytes
	seal, err := bundleSealBytes(members, l.KeyID, l.Pair)
	if err != nil {
		t.Fatal(err)
	}
	members["BUNDLE_SEAL.json"] = seal
}
