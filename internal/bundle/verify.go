package bundle

import (
	"archive/tar"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

const (
	TrustNotVerified          = "NOT_VERIFIED"
	TrustInternallyConsistent = "INTERNALLY_CONSISTENT"
	TrustIdentityTrusted      = "IDENTITY_TRUSTED"
	TrustIdentityMismatch     = "IDENTITY_MISMATCH"

	OverallVerified      = "VERIFIED"
	OverallIndeterminate = "TRUST_INDETERMINATE"
	OverallNotTrusted    = "NOT_TRUSTED"
	OverallInvalid       = "INVALID"
)

var (
	hex64Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fullKeyIDPattern  = regexp.MustCompile(`^ueg:sha256:[0-9a-f]{64}$`)
	identityIDPattern = regexp.MustCompile(`^ueg:identity:sha256:[0-9a-f]{64}$`)
)

// Options supplies trust information that cannot truthfully come from inside
// the bundle being verified.
type Options struct {
	ExpectedKeyID             string
	ExpectedIdentityID        string
	ExternalCheckpointPath    string
	ExternalAnchorPath        string
	TrustStore                string
	MinimumCheckpointSequence *int
	MinimumCheckpointDigest   string
	RequireCurrentStatus      bool
}

// Result is the verdict on a bundle. TrustVerdict deliberately distinguishes
// cryptographic self-consistency from identity trust anchored outside it.
type Result struct {
	OK            bool     `json:"ok"`
	Reason        string   `json:"reason"`
	TrustVerdict  string   `json:"trust_verdict"`
	ExpectedKeyID string   `json:"expected_key_id,omitempty"`
	ReceiptCount  int      `json:"receipt_count"`
	SigningKeyIDs []string `json:"signing_key_ids"`
	Checks        []string `json:"checks_passed"`
	BundleVersion string   `json:"bundle_version,omitempty"`
	ReasonCode    string   `json:"reason_code,omitempty"`

	Signature              string `json:"SIGNATURE,omitempty"`
	BundleLedgerIntegrity  string `json:"BUNDLE_LEDGER_INTEGRITY,omitempty"`
	IdentityContinuity     string `json:"IDENTITY_CONTINUITY,omitempty"`
	LifecycleChain         string `json:"LIFECYCLE_CHAIN,omitempty"`
	SigningKeyStatus       string `json:"SIGNING_KEY_STATUS,omitempty"`
	EpochAuthorization     string `json:"EPOCH_AUTHORIZATION,omitempty"`
	EvidenceAnchor         string `json:"EVIDENCE_ANCHOR,omitempty"`
	CheckpointAuthenticity string `json:"CHECKPOINT_AUTHENTICITY,omitempty"`
	CheckpointSource       string `json:"CHECKPOINT_SOURCE,omitempty"`
	CheckpointSequence     string `json:"CHECKPOINT_SEQUENCE,omitempty"`
	CheckpointFreshness    string `json:"CHECKPOINT_FRESHNESS,omitempty"`
	EvidenceTimeAssurance  string `json:"EVIDENCE_TIME_ASSURANCE,omitempty"`
	OverallTrust           string `json:"OVERALL_TRUST,omitempty"`
	IdentityID             string `json:"identity_id,omitempty"`
	LifecycleSequence      int    `json:"lifecycle_sequence,omitempty"`
	LifecycleDigest        string `json:"lifecycle_digest,omitempty"`
}

func fail(format string, args ...any) Result {
	return Result{
		OK: false, Reason: fmt.Sprintf(format, args...), TrustVerdict: TrustNotVerified,
		ReasonCode: "EVIDENCE_INVALID", OverallTrust: OverallInvalid,
	}
}

// Verify proves bundle integrity without asserting a real-world signer
// identity. Call VerifyWithOptions with an externally pinned key id for that.
func Verify(bundlePath string) Result {
	return VerifyWithOptions(bundlePath, Options{})
}

// VerifyWithOptions validates the archive, strict JSON, manifest, revocations,
// key identities, signatures, receipt chain, petitions, and seals.
func VerifyWithOptions(bundlePath string, options Options) Result {
	members, err := readTarGz(bundlePath)
	if err != nil {
		return fail("%v", err)
	}

	res := Result{OK: true, TrustVerdict: TrustInternallyConsistent, Checks: []string{}}
	manifest, r := verifyManifest(members)
	if !r.OK {
		return r
	}
	res.Checks = append(res.Checks, "manifest matches member bytes under strict JSON parsing")
	if manifest.Version == bPlusManifestVersion {
		return verifyBPlusBundle(members, manifest, options)
	}

	trust, r := loadTrustRoots(members, manifest.Version == "v1")
	if !r.OK {
		return r
	}
	res.Checks = append(res.Checks, fmt.Sprintf("%d active trust-root alias(es), revocations enforced", len(trust)))

	bundleSigner, r := verifyBundleSeal(members, trust)
	if !r.OK {
		return r
	}
	res.Checks = append(res.Checks, "bundle seal identity, signature, seal id, and merkle root verified")

	receipts, r := parseReceipts(members)
	if !r.OK {
		return r
	}
	res.ReceiptCount = len(receipts)

	chain := ledger.Verify(receipts, trust)
	if !chain.OK {
		return fail("receipt chain: %s", strings.Join(chain.Findings, "; "))
	}
	res.Checks = append(res.Checks, fmt.Sprintf("%d receipt ids re-derived and signatures verified", chain.Checked))

	if data, ok := members["petitions.ndjson"]; ok {
		petitions, err := parsePetitions(data)
		if err != nil {
			return fail("petitions.ndjson: %v", err)
		}
		bindRes := ledger.VerifyPetitions(receipts, petitions)
		if !bindRes.OK {
			return fail("petition binding: %s", strings.Join(bindRes.Findings, "; "))
		}
		res.Checks = append(res.Checks, "every receipt's petition_hash matches the strictly parsed stored request")
	}

	receiptSealSigner, r := verifyReceiptSeal(members, receipts, trust)
	if !r.OK {
		return r
	}
	res.Checks = append(res.Checks, "receipt window seal verified")

	claimedSigners := []string{bundleSigner, receiptSealSigner}
	for _, receipt := range receipts {
		claimedSigners = append(claimedSigners, receipt.SigningKeyID)
	}
	actual, err := canonicalSignerIDs(claimedSigners, trust)
	if err != nil {
		return fail("signing identity: %v", err)
	}
	res.SigningKeyIDs = actual

	if options.ExpectedKeyID == "" {
		res.Reason = TrustInternallyConsistent
		res.Checks = append(res.Checks, "self-contained evidence is internally consistent; signer identity was not externally anchored")
		return res
	}
	res.ExpectedKeyID = options.ExpectedKeyID
	if !fullKeyIDPattern.MatchString(options.ExpectedKeyID) || len(actual) != 1 || actual[0] != options.ExpectedKeyID {
		res.OK = false
		res.Reason = fmt.Sprintf("expected signing identity %s, bundle was signed by %s", options.ExpectedKeyID, strings.Join(actual, ", "))
		res.TrustVerdict = TrustIdentityMismatch
		return res
	}
	res.TrustVerdict = TrustIdentityTrusted
	res.Reason = TrustIdentityTrusted
	res.Checks = append(res.Checks, "every signing key matches the externally supplied complete fingerprint")
	return res
}

func canonicalSignerIDs(claimed []string, trust map[string]*keys.Pair) ([]string, error) {
	unique := map[string]struct{}{}
	for _, id := range claimed {
		pair, ok := trust[id]
		if !ok {
			return nil, fmt.Errorf("claimed signing key is not an active trust root: %s", id)
		}
		canonicalID, err := pair.KeyID()
		if err != nil {
			return nil, err
		}
		unique[canonicalID] = struct{}{}
	}
	out := make([]string, 0, len(unique))
	for id := range unique {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

func readTarGz(path string) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()

	members := map[string][]byte{}
	total := 0
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("non-regular archive member is not permitted: %s", hdr.Name)
		}
		if !safeName(hdr.Name) {
			return nil, fmt.Errorf("unsafe member name: %s", hdr.Name)
		}
		if _, duplicate := members[hdr.Name]; duplicate {
			return nil, fmt.Errorf("duplicate member: %s", hdr.Name)
		}
		if len(members) >= maxFiles {
			return nil, fmt.Errorf("too many files (limit %d)", maxFiles)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFileBytes+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maxFileBytes {
			return nil, fmt.Errorf("member too large: %s", hdr.Name)
		}
		total += len(data)
		if total > maxTotalBytes {
			return nil, fmt.Errorf("bundle too large (limit %d bytes)", maxTotalBytes)
		}
		members[hdr.Name] = data
	}
	return members, nil
}

type manifestDocument struct {
	CreatedAt            string            `json:"created_at"`
	Files                map[string]string `json:"files"`
	Version              string            `json:"version"`
	IdentityID           string            `json:"identity_id,omitempty"`
	CheckpointSequence   *int              `json:"checkpoint_sequence,omitempty"`
	CheckpointDigest     string            `json:"checkpoint_digest,omitempty"`
	EvidenceAnchorDigest string            `json:"evidence_anchor_digest,omitempty"`
}

func verifyManifest(members map[string][]byte) (manifestDocument, Result) {
	raw, ok := members["MANIFEST.json"]
	if !ok {
		return manifestDocument{}, fail("missing MANIFEST.json")
	}
	var manifest manifestDocument
	if err := strictjson.UnmarshalExact(raw, &manifest); err != nil {
		return manifestDocument{}, fail("invalid MANIFEST.json: %v", err)
	}
	if manifest.Version != "v1" && manifest.Version != "v2" && manifest.Version != bPlusManifestVersion {
		return manifestDocument{}, fail("manifest version must be v1, v2, or bplus-v1")
	}
	if manifest.CreatedAt == "" {
		return manifestDocument{}, fail("manifest.created_at must be a non-empty string")
	}
	if len(manifest.Files) == 0 {
		return manifestDocument{}, fail("manifest.files must be a non-empty object")
	}
	requiredMembers := []string{"receipts.ndjson", "trust_roots.json", "revocations.json", "seals.json"}
	if manifest.Version == bPlusManifestVersion {
		requiredMembers = append(requiredMembers, "petitions.ndjson", "identity/genesis.json", "identity/lifecycle.ndjson",
			"identity/card.json", "identity/checkpoint.json", "identity/evidence_anchor.json")
		if !identityIDPattern.MatchString(manifest.IdentityID) || manifest.CheckpointSequence == nil || *manifest.CheckpointSequence < 0 ||
			!hex64Pattern.MatchString(manifest.CheckpointDigest) || !hex64Pattern.MatchString(manifest.EvidenceAnchorDigest) {
			return manifestDocument{}, fail("B+ manifest authority fields are invalid")
		}
	} else if manifest.IdentityID != "" || manifest.CheckpointSequence != nil || manifest.CheckpointDigest != "" || manifest.EvidenceAnchorDigest != "" {
		return manifestDocument{}, fail("legacy manifest contains B+ authority fields")
	}
	for _, required := range requiredMembers {
		if _, ok := manifest.Files[required]; !ok {
			return manifestDocument{}, fail("manifest is missing required entry: %s", required)
		}
	}
	allowed := map[string]bool{"MANIFEST.json": true, "BUNDLE_SEAL.json": true}
	for name, hash := range manifest.Files {
		if !safeName(name) || name == "MANIFEST.json" || name == "BUNDLE_SEAL.json" {
			return manifestDocument{}, fail("manifest contains an invalid member name: %s", name)
		}
		if !hex64Pattern.MatchString(hash) {
			return manifestDocument{}, fail("manifest hash for %s is not 64 lowercase hex characters", name)
		}
		allowed[name] = true
	}
	for name := range members {
		if !allowed[name] {
			return manifestDocument{}, fail("archive holds a file the manifest does not list: %s", name)
		}
	}
	for name, want := range manifest.Files {
		data, ok := members[name]
		if !ok {
			return manifestDocument{}, fail("manifest names a missing file: %s", name)
		}
		if canon.SHA256Hex(data) != want {
			return manifestDocument{}, fail("hash mismatch: %s", name)
		}
	}
	return manifest, Result{OK: true}
}

type trustRootsDocument struct {
	Keys map[string]string `json:"ed25519_public_keys"`
}

func loadTrustRoots(members map[string][]byte, allowLegacy bool) (map[string]*keys.Pair, Result) {
	raw, ok := members["trust_roots.json"]
	if !ok {
		return nil, fail("missing trust_roots.json")
	}
	var document trustRootsDocument
	if err := strictjson.UnmarshalExact(raw, &document); err != nil {
		return nil, fail("invalid trust_roots.json: %v", err)
	}
	if len(document.Keys) == 0 {
		return nil, fail("trust_roots.json holds no public keys")
	}

	all := map[string]*keys.Pair{}
	canonicalByClaim := map[string]string{}
	for id, pemText := range document.Keys {
		pair, err := keys.LoadPublicPEMText(pemText)
		if err != nil {
			return nil, fail("trust root %s: %v", id, err)
		}
		if err := pair.ValidateKeyID(id, allowLegacy); err != nil {
			return nil, fail("trust root %s: %v", id, err)
		}
		canonicalID, err := pair.KeyID()
		if err != nil {
			return nil, fail("trust root %s: %v", id, err)
		}
		all[id] = pair
		canonicalByClaim[id] = canonicalID
	}

	revokedIDs, err := parseRevocations(members["revocations.json"])
	if err != nil {
		return nil, fail("invalid revocations.json: %v", err)
	}
	revokedCanonical := map[string]struct{}{}
	for _, id := range revokedIDs {
		canonicalID, ok := canonicalByClaim[id]
		if !ok {
			return nil, fail("revocation names a key that is not bound in trust_roots.json: %s", id)
		}
		revokedCanonical[canonicalID] = struct{}{}
	}

	active := map[string]*keys.Pair{}
	for id, pair := range all {
		if _, revoked := revokedCanonical[canonicalByClaim[id]]; revoked {
			continue
		}
		active[id] = pair
	}
	if len(active) == 0 {
		return nil, fail("every trust root is revoked")
	}
	return active, Result{OK: true}
}

func parseRevocations(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("missing revocation data")
	}
	var value any
	if err := strictjson.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	var ids []string
	switch typed := value.(type) {
	case []any:
		for index, item := range typed {
			switch entry := item.(type) {
			case string:
				ids = append(ids, entry)
			case map[string]any:
				id, err := parseRevocationRecord(entry)
				if err != nil {
					return nil, fmt.Errorf("entry %d: %w", index, err)
				}
				ids = append(ids, id)
			default:
				return nil, fmt.Errorf("entry %d must be a key id string or revocation object", index)
			}
		}
	case map[string]any:
		if len(typed) != 1 {
			return nil, fmt.Errorf("object form permits only revoked_key_ids")
		}
		rawIDs, ok := typed["revoked_key_ids"].([]any)
		if !ok {
			return nil, fmt.Errorf("revoked_key_ids must be an array")
		}
		for index, item := range rawIDs {
			id, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("revoked_key_ids[%d] must be a string", index)
			}
			ids = append(ids, id)
		}
	default:
		return nil, fmt.Errorf("top level must be an array or revoked_key_ids object")
	}
	seen := map[string]struct{}{}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("revoked key id must not be empty")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("duplicate revoked key id: %s", id)
		}
		seen[id] = struct{}{}
	}
	return ids, nil
}

func parseRevocationRecord(record map[string]any) (string, error) {
	for field, value := range record {
		switch field {
		case "key_id", "reason", "revoked_at":
			if _, ok := value.(string); !ok {
				return "", fmt.Errorf("%s must be a string", field)
			}
		default:
			return "", fmt.Errorf("unexpected field %s", field)
		}
	}
	id, ok := record["key_id"].(string)
	if !ok || strings.TrimSpace(id) == "" {
		return "", fmt.Errorf("key_id is required")
	}
	return id, nil
}

type bundleSealDocument struct {
	CreatedAt         string `json:"created_at"`
	ManifestSHA256    string `json:"manifest_sha256"`
	MembersMerkleRoot string `json:"members_merkle_root"`
	SealID            string `json:"seal_id"`
	SignatureB64      string `json:"signature_b64"`
	SigningKeyID      string `json:"signing_key_id"`
	Version           string `json:"version"`
}

func verifyBundleSeal(members map[string][]byte, trust map[string]*keys.Pair) (string, Result) {
	raw, ok := members["BUNDLE_SEAL.json"]
	if !ok {
		return "", fail("missing BUNDLE_SEAL.json")
	}
	var seal bundleSealDocument
	if err := strictjson.UnmarshalExact(raw, &seal); err != nil {
		return "", fail("invalid BUNDLE_SEAL.json: %v", err)
	}
	if seal.Version != "v1" || seal.CreatedAt == "" || !hex64Pattern.MatchString(seal.SealID) || !hex64Pattern.MatchString(seal.ManifestSHA256) || !hex64Pattern.MatchString(seal.MembersMerkleRoot) {
		return "", fail("invalid BUNDLE_SEAL.json: required values do not conform to Bundle Seal v1")
	}
	pair, ok := trust[seal.SigningKeyID]
	if !ok {
		return "", fail("bundle seal names a key that is not an active trust root: %s", seal.SigningKeyID)
	}
	if seal.ManifestSHA256 != canon.SHA256Hex(members["MANIFEST.json"]) {
		return "", fail("bundle seal does not match MANIFEST.json")
	}

	names := make([]string, 0, len(members))
	for name := range members {
		if name != "BUNDLE_SEAL.json" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	leaves := make([][]byte, 0, len(names))
	for _, name := range names {
		leaves = append(leaves, canon.SHA256([]byte(name+":"+canon.SHA256Hex(members[name]))))
	}
	if seal.MembersMerkleRoot != canon.MerkleRootHex(leaves) {
		return "", fail("bundle seal merkle root does not match the archive contents")
	}

	base := map[string]any{
		"created_at":          seal.CreatedAt,
		"manifest_sha256":     seal.ManifestSHA256,
		"members_merkle_root": seal.MembersMerkleRoot,
		"signing_key_id":      seal.SigningKeyID,
		"version":             seal.Version,
	}
	sealID, err := canon.HashJCS(base)
	if err != nil || sealID != seal.SealID {
		return "", fail("bundle seal id does not match its contents")
	}
	body := cloneMap(base)
	body["seal_id"] = seal.SealID
	payload, err := canon.Canonicalize(body)
	if err != nil {
		return "", fail("bundle seal is not canonicalizable: %v", err)
	}
	if !pair.VerifyB64(payload, seal.SignatureB64) {
		return "", fail("bundle seal signature is invalid")
	}
	return seal.SigningKeyID, Result{OK: true}
}

func parseReceipts(members map[string][]byte) ([]*ledger.Receipt, Result) {
	raw, ok := members["receipts.ndjson"]
	if !ok {
		return nil, fail("missing receipts.ndjson")
	}
	var receipts []*ledger.Receipt
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		receipt, err := ledger.ParseReceiptStrict([]byte(line))
		if err != nil {
			return nil, fail("receipts.ndjson: %v", err)
		}
		receipts = append(receipts, receipt)
	}
	if len(receipts) == 0 {
		return nil, fail("receipts.ndjson holds no receipts")
	}
	return receipts, Result{OK: true}
}

func parsePetitions(raw []byte) ([]ledger.Petition, error) {
	var out []ledger.Petition
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var petition ledger.Petition
		if err := strictjson.Unmarshal([]byte(line), &petition); err != nil {
			return nil, err
		}
		out = append(out, petition)
	}
	return out, nil
}

type receiptSealWindow struct {
	EndISO8601   string `json:"end_iso8601"`
	StartISO8601 string `json:"start_iso8601"`
	Type         string `json:"type"`
}

type receiptSealDocument struct {
	FirstReceiptID string            `json:"first_receipt_id"`
	LastReceiptID  string            `json:"last_receipt_id"`
	MerkleRoot     string            `json:"merkle_root"`
	PolicyHashSet  []string          `json:"policy_hash_set"`
	SealID         string            `json:"seal_id"`
	SignatureB64   string            `json:"signature_b64"`
	SigningKeyID   string            `json:"signing_key_id"`
	Window         receiptSealWindow `json:"window"`
}

func verifyReceiptSeal(members map[string][]byte, receipts []*ledger.Receipt, trust map[string]*keys.Pair) (string, Result) {
	raw, ok := members["seals.json"]
	if !ok {
		return "", fail("missing seals.json")
	}
	var seals []receiptSealDocument
	if err := strictjson.UnmarshalExact(raw, &seals); err != nil {
		return "", fail("invalid seals.json: %v", err)
	}
	if len(seals) != 1 {
		return "", fail("seals.json must contain exactly one receipt-window seal")
	}
	seal := seals[0]
	if !hex64Pattern.MatchString(seal.FirstReceiptID) || !hex64Pattern.MatchString(seal.LastReceiptID) || !hex64Pattern.MatchString(seal.MerkleRoot) || !hex64Pattern.MatchString(seal.SealID) || seal.Window.Type != "time" || seal.Window.StartISO8601 == "" || seal.Window.EndISO8601 == "" {
		return "", fail("invalid seals.json: required values do not conform to Seal v1")
	}
	for _, hash := range seal.PolicyHashSet {
		if !hex64Pattern.MatchString(hash) {
			return "", fail("invalid seals.json: policy_hash_set contains a non-hash value")
		}
	}
	pair, ok := trust[seal.SigningKeyID]
	if !ok {
		return "", fail("receipt seal names a key that is not an active trust root: %s", seal.SigningKeyID)
	}
	if seal.FirstReceiptID != receipts[0].ReceiptID {
		return "", fail("receipt seal first_receipt_id does not match the chain")
	}
	if seal.LastReceiptID != receipts[len(receipts)-1].ReceiptID {
		return "", fail("receipt seal last_receipt_id does not match the chain")
	}

	leaves := make([][]byte, 0, len(receipts))
	policySet := map[string]struct{}{}
	for _, receipt := range receipts {
		bytes, err := hex.DecodeString(receipt.ReceiptID)
		if err != nil {
			return "", fail("receipt id is not hex")
		}
		leaves = append(leaves, bytes)
		policySet[receipt.PolicyHash] = struct{}{}
	}
	if seal.MerkleRoot != canon.MerkleRootHex(leaves) {
		return "", fail("receipt seal merkle root does not match the chain")
	}
	wantPolicies := make([]string, 0, len(policySet))
	for hash := range policySet {
		wantPolicies = append(wantPolicies, hash)
	}
	sort.Strings(wantPolicies)
	if strings.Join(wantPolicies, "\x00") != strings.Join(seal.PolicyHashSet, "\x00") {
		return "", fail("receipt seal policy_hash_set does not match the chain")
	}

	base := map[string]any{
		"first_receipt_id": seal.FirstReceiptID,
		"last_receipt_id":  seal.LastReceiptID,
		"merkle_root":      seal.MerkleRoot,
		"policy_hash_set":  seal.PolicyHashSet,
		"signing_key_id":   seal.SigningKeyID,
		"window": map[string]any{
			"end_iso8601":   seal.Window.EndISO8601,
			"start_iso8601": seal.Window.StartISO8601,
			"type":          seal.Window.Type,
		},
	}
	sealID, err := canon.HashJCS(base)
	if err != nil || sealID != seal.SealID {
		return "", fail("receipt seal id does not match its contents")
	}
	body := cloneMap(base)
	body["seal_id"] = seal.SealID
	payload, err := canon.Canonicalize(body)
	if err != nil {
		return "", fail("receipt seal is not canonicalizable: %v", err)
	}
	if !pair.VerifyB64(payload, seal.SignatureB64) {
		return "", fail("receipt seal signature is invalid")
	}
	return seal.SigningKeyID, Result{OK: true}
}
