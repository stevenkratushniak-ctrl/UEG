// Package bundle writes and reads the offline evidence bundle: a single
// .tar.gz holding the receipt chain, the public keys, and two signed anchors
// that make silent editing of the archive detectable.
//
// The layout is Reality Layer V1's, unchanged, so the Python verifier in
// verifier/ validates a bundle this Go code produced. Two independent
// implementations agreeing is the point.
package bundle

import (
	"archive/tar"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
)

const (
	maxTotalBytes = 50 * 1024 * 1024
	maxFileBytes  = 10 * 1024 * 1024
	maxFiles      = 200
)

var (
	ErrDestinationExists = errors.New("bundle: destination already exists")
	ErrEvidenceInvalid   = errors.New("bundle: evidence is not valid for export")
	ErrExportTooLarge    = errors.New("bundle: evidence is too large for one verifiable bundle")
	ErrWriteFailed       = errors.New("bundle: export could not be written safely")
)

// Build writes a signed bundle for the ledger to outputPath.
func Build(l *ledger.Ledger, outputPath string) error {
	outputPath, err := availableDestination(outputPath)
	if err != nil {
		return err
	}
	if l.BPlus {
		return buildBPlus(l, outputPath)
	}
	receiptBytes, err := os.ReadFile(l.ReceiptsPath)
	if err != nil {
		return invalidEvidenceError("cannot read receipts: %v", err)
	}
	receipts, parsed := parseReceipts(map[string][]byte{"receipts.ndjson": receiptBytes})
	if !parsed.OK {
		return invalidEvidenceError("%s", parsed.Reason)
	}
	if res := ledger.Verify(receipts, l.TrustSelf()); !res.OK {
		return invalidEvidenceError("receipt verification failed: %s", strings.Join(res.Findings, "; "))
	}
	petitionBytes, err := os.ReadFile(l.PetitionsPath)
	if err != nil {
		return invalidEvidenceError("cannot read stored requests: %v", err)
	}
	petitions, err := parsePetitions(petitionBytes)
	if err != nil {
		return invalidEvidenceError("stored requests are malformed: %v", err)
	}
	if res := ledger.VerifyPetitions(receipts, petitions); !res.OK {
		return invalidEvidenceError("stored request verification failed: %s", strings.Join(res.Findings, "; "))
	}
	pubPEM, err := l.Pair.PublicPEM()
	if err != nil {
		return fmt.Errorf("%w: cannot encode the public trust root: %v", ErrEvidenceInvalid, err)
	}

	members := map[string][]byte{}
	members["receipts.ndjson"] = receiptBytes
	members["petitions.ndjson"] = petitionBytes
	members["revocations.json"] = []byte("[]\n")

	trustKeys := map[string]string{l.KeyID: string(pubPEM)}
	manifestVersion := "v2"
	for _, receipt := range receipts {
		if err := l.Pair.ValidateKeyID(receipt.SigningKeyID, true); err != nil {
			return fmt.Errorf("bundle: receipt names a signing key that does not match the ledger key: %s", receipt.SigningKeyID)
		}
		trustKeys[receipt.SigningKeyID] = string(pubPEM)
		if err := l.Pair.ValidateKeyID(receipt.SigningKeyID, false); err != nil {
			manifestVersion = "v1"
		}
	}
	trustRoots, err := json.MarshalIndent(map[string]any{
		"ed25519_public_keys": trustKeys,
	}, "", "  ")
	if err != nil {
		return err
	}
	members["trust_roots.json"] = trustRoots

	seal, err := receiptSeal(receipts, l.KeyID, l.Pair)
	if err != nil {
		return err
	}
	sealsJSON, err := json.MarshalIndent([]any{seal}, "", "  ")
	if err != nil {
		return err
	}
	members["seals.json"] = append(sealsJSON, '\n')

	fileHashes := map[string]any{}
	for name, data := range members {
		fileHashes[name] = canon.SHA256Hex(data)
	}
	manifest, err := json.MarshalIndent(map[string]any{
		"created_at": nowISO(),
		"files":      fileHashes,
		"version":    manifestVersion,
	}, "", "  ")
	if err != nil {
		return err
	}
	members["MANIFEST.json"] = manifest

	bundleSeal, err := bundleSealBytes(members, l.KeyID, l.Pair)
	if err != nil {
		return err
	}
	members["BUNDLE_SEAL.json"] = bundleSeal

	if err := validateMemberLimits(members); err != nil {
		return err
	}
	return writeTarGzAtomic(outputPath, members)
}

func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00")
}

// receiptSeal signs the window of receipts: its first and last id, the Merkle
// root over every id, and the set of policies that were in force.
func receiptSeal(receipts []*ledger.Receipt, keyID string, pair *keys.Pair) (map[string]any, error) {
	ids := make([]string, 0, len(receipts))
	leaves := make([][]byte, 0, len(receipts))
	policySet := map[string]bool{}
	for _, r := range receipts {
		ids = append(ids, r.ReceiptID)
		raw, err := hex.DecodeString(r.ReceiptID)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, raw)
		policySet[r.PolicyHash] = true
	}
	policies := make([]any, 0, len(policySet))
	for p := range policySet {
		policies = append(policies, p)
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].(string) < policies[j].(string) })

	base := map[string]any{
		"first_receipt_id": ids[0],
		"last_receipt_id":  ids[len(ids)-1],
		"merkle_root":      canon.MerkleRootHex(leaves),
		"policy_hash_set":  policies,
		"signing_key_id":   keyID,
		"window": map[string]any{
			"end_iso8601":   receipts[len(receipts)-1].TimestampISO8601,
			"start_iso8601": receipts[0].TimestampISO8601,
			"type":          "time",
		},
	}
	sealID, err := canon.HashJCS(base)
	if err != nil {
		return nil, err
	}
	toSign := cloneMap(base)
	toSign["seal_id"] = sealID
	payload, err := canon.Canonicalize(toSign)
	if err != nil {
		return nil, err
	}
	sig, err := pair.SignB64(payload)
	if err != nil {
		return nil, err
	}
	seal := cloneMap(toSign)
	seal["signature_b64"] = sig
	return seal, nil
}

// bundleSealBytes anchors the manifest itself, so rewriting MANIFEST.json plus
// the files it names is still detectable.
func bundleSealBytes(members map[string][]byte, keyID string, pair *keys.Pair) ([]byte, error) {
	names := make([]string, 0, len(members))
	for name := range members {
		if name == "BUNDLE_SEAL.json" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	leaves := make([][]byte, 0, len(names))
	for _, name := range names {
		leaves = append(leaves, canon.SHA256([]byte(name+":"+canon.SHA256Hex(members[name]))))
	}

	base := map[string]any{
		"created_at":          nowISO(),
		"manifest_sha256":     canon.SHA256Hex(members["MANIFEST.json"]),
		"members_merkle_root": canon.MerkleRootHex(leaves),
		"signing_key_id":      keyID,
		"version":             "v1",
	}
	sealID, err := canon.HashJCS(base)
	if err != nil {
		return nil, err
	}
	toSign := cloneMap(base)
	toSign["seal_id"] = sealID
	payload, err := canon.Canonicalize(toSign)
	if err != nil {
		return nil, err
	}
	sig, err := pair.SignB64(payload)
	if err != nil {
		return nil, err
	}
	seal := cloneMap(toSign)
	seal["signature_b64"] = sig
	return json.MarshalIndent(seal, "", "  ")
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// writeTarGz is retained for tests that deliberately construct malformed
// archives. Product exports use writeTarGzAtomic below.
func writeTarGz(outputPath string, members map[string][]byte) error {
	f, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	return writeTarGzFile(f, members)
}

func writeTarGzAtomic(outputPath string, members map[string][]byte) (err error) {
	outputPath, err = availableDestination(outputPath)
	if err != nil {
		return err
	}
	parent := filepath.Dir(outputPath)
	temp, err := os.CreateTemp(parent, exportTempPattern(outputPath))
	if err != nil {
		return fmt.Errorf("%w: cannot create a temporary file in the destination folder: %v", ErrWriteFailed, err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("%w: cannot protect the temporary export: %v", ErrWriteFailed, err)
	}
	if err := writeTarGzFile(temp, members); err != nil {
		return fmt.Errorf("%w: the temporary export was incomplete: %v", ErrWriteFailed, err)
	}
	verified := Verify(tempPath)
	if !verified.OK {
		return fmt.Errorf("%w: the temporary export did not pass independent verification: %s", ErrEvidenceInvalid, verified.Reason)
	}
	published, err := publishNoReplace(tempPath, outputPath)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w; choose a new filename or move the existing file: %s", ErrDestinationExists, outputPath)
		}
		if published {
			return fmt.Errorf("%w: the complete bundle reached %s, but its final durability check failed; verify it before relying on it: %v", ErrWriteFailed, outputPath, err)
		}
		return fmt.Errorf("%w: the destination was not changed: %v", ErrWriteFailed, err)
	}
	return nil
}

func invalidEvidenceError(format string, args ...any) error {
	detail := fmt.Sprintf(format, args...)
	return fmt.Errorf("%w: %s; no export was created; run ueg ledger to inspect the local evidence and restore changed evidence from a trusted backup", ErrEvidenceInvalid, detail)
}

func exportTempPattern(outputPath string) string {
	base := filepath.Base(outputPath)
	var clean strings.Builder
	for _, r := range base {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r) {
			clean.WriteRune(r)
		} else {
			clean.WriteByte('_')
		}
	}
	if clean.Len() == 0 {
		clean.WriteString("bundle")
	}
	return "." + clean.String() + ".ueg-export-*.partial"
}

func writeTarGzFile(f *os.File, members map[string][]byte) error {
	names := make([]string, 0, len(members))
	for name := range members {
		if !safeName(name) {
			return fmt.Errorf("bundle: unsafe member name %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	closed := false
	defer func() {
		if !closed {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
		}
	}()
	for _, name := range names {
		data := members[name]
		hdr := &tar.Header{
			Name:     name,
			Size:     int64(len(data)),
			Mode:     0o644,
			ModTime:  time.Unix(0, 0).UTC(),
			Uid:      0,
			Gid:      0,
			Typeflag: tar.TypeReg,
			Format:   tar.FormatGNU,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func availableDestination(outputPath string) (string, error) {
	if strings.TrimSpace(outputPath) == "" {
		return "", fmt.Errorf("%w: choose an output filename", ErrWriteFailed)
	}
	abs, err := filepath.Abs(outputPath)
	if err != nil {
		return "", fmt.Errorf("%w: cannot resolve the destination: %v", ErrWriteFailed, err)
	}
	if _, err := os.Lstat(abs); err == nil {
		return "", fmt.Errorf("%w; choose a new filename or move the existing file: %s", ErrDestinationExists, abs)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("%w: cannot inspect the destination: %v", ErrWriteFailed, err)
	}
	parent := filepath.Dir(abs)
	info, err := os.Stat(parent)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: destination folder does not exist; create it first or choose an existing folder: %s", ErrWriteFailed, parent)
		}
		return "", fmt.Errorf("%w: cannot inspect the destination folder: %v", ErrWriteFailed, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: destination parent is not a folder: %s", ErrWriteFailed, parent)
	}
	return abs, nil
}

func validateMemberLimits(members map[string][]byte) error {
	if len(members) > maxFiles {
		return fmt.Errorf("%w: %d files exceeds the %d-file verifier limit; retain the local evidence and export a smaller supported set", ErrExportTooLarge, len(members), maxFiles)
	}
	total := 0
	for name, data := range members {
		if len(data) > maxFileBytes {
			return fmt.Errorf("%w: %s is %d bytes and exceeds the %d-byte verifier limit; retain the local evidence and use a supported rollover workflow", ErrExportTooLarge, name, len(data), maxFileBytes)
		}
		total += len(data)
		if total > maxTotalBytes {
			return fmt.Errorf("%w: %d bytes exceeds the %d-byte verifier limit; retain the local evidence and use a supported rollover workflow", ErrExportTooLarge, total, maxTotalBytes)
		}
	}
	return nil
}

func safeName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, `\:`) {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for index := 0; index < len(part); index++ {
			character := part[index]
			if character >= 'a' && character <= 'z' ||
				character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' ||
				character == '.' || character == '_' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}
