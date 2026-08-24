// Package ledger writes and verifies the append-only receipt chain.
//
// A receipt is a Reality Layer V1 Receipt v1 object: receipt_id is the SHA-256
// of the canonical form of every other field except the signature, the
// signature is Ed25519 over that id, and each receipt names the one before it.
// Changing any recorded fact changes the id; changing the id invalidates the
// signature; removing a receipt breaks the chain.
package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/identity"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

// EngineVersion identifies the code that produced a receipt.
const EngineVersion = "ueg/2.2.0-v3-candidate.1"

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

var ErrRecoveryRequired = errors.New("ledger: an interrupted evidence write requires explicit recovery")

// Receipt is Reality Layer Receipt v1. Field names and the absence of any
// extra field are fixed by contract/schemas/receipt.v1.schema.json.
type Receipt struct {
	ReceiptID         string          `json:"receipt_id"`
	PrevReceiptID     *string         `json:"prev_receipt_id"`
	SequenceNo        int             `json:"sequence_no"`
	TimestampISO8601  string          `json:"timestamp_iso8601"`
	TimeSource        string          `json:"time_source"`
	Actor             string          `json:"actor"`
	AdapterDegraded   bool            `json:"adapter_degraded"`
	PetitionHash      string          `json:"petition_hash"`
	PetitionSummary   PetitionSummary `json:"petition_summary"`
	AdmissionOutcome  string          `json:"admission_outcome"`
	ExpressionOutcome string          `json:"expression_outcome"`
	PolicyHash        string          `json:"policy_hash"`
	EngineVersion     string          `json:"engine_version"`
	ClauseIDs         []string        `json:"clause_ids"`
	EvaluationHash    string          `json:"evaluation_hash"`
	PassportRef       *string         `json:"passport_ref"`
	SigningKeyID      string          `json:"signing_key_id"`
	SignatureB64      string          `json:"signature_b64"`
}

// PetitionSummary is the three-field digest of a request the contract carries
// in the clear. The full request lives in petitions.ndjson and is bound by
// petition_hash.
type PetitionSummary struct {
	Surface string `json:"surface"`
	Action  string `json:"action"`
	Target  string `json:"target"`
}

// core is the canonical form receipt_id is taken over: every field except
// receipt_id and signature_b64.
func (r *Receipt) core() map[string]any {
	var prev any
	if r.PrevReceiptID != nil {
		prev = *r.PrevReceiptID
	}
	var passport any
	if r.PassportRef != nil {
		passport = *r.PassportRef
	}
	clauses := make([]any, 0, len(r.ClauseIDs))
	for _, c := range r.ClauseIDs {
		clauses = append(clauses, c)
	}
	return map[string]any{
		"actor":              r.Actor,
		"adapter_degraded":   r.AdapterDegraded,
		"admission_outcome":  r.AdmissionOutcome,
		"clause_ids":         clauses,
		"engine_version":     r.EngineVersion,
		"evaluation_hash":    r.EvaluationHash,
		"expression_outcome": r.ExpressionOutcome,
		"passport_ref":       passport,
		"petition_hash":      r.PetitionHash,
		"petition_summary": map[string]any{
			"action":  r.PetitionSummary.Action,
			"surface": r.PetitionSummary.Surface,
			"target":  r.PetitionSummary.Target,
		},
		"policy_hash":       r.PolicyHash,
		"prev_receipt_id":   prev,
		"sequence_no":       r.SequenceNo,
		"signing_key_id":    r.SigningKeyID,
		"time_source":       r.TimeSource,
		"timestamp_iso8601": r.TimestampISO8601,
	}
}

// ComputeID returns the receipt_id implied by the receipt's contents.
func (r *Receipt) ComputeID() (string, error) {
	return canon.HashJCS(r.core())
}

// Petition is the full request UEG acted on. It is not part of the Receipt v1
// schema; it is stored beside the chain and bound to it by petition_hash, so
// the contract stays unmodified while the evidence stays complete.
type Petition map[string]any

// Ledger is an append-only receipt chain on disk.
type Ledger struct {
	Home          string
	ReceiptsPath  string
	PetitionsPath string
	KeyID         string
	Pair          *keys.Pair
	// BPlus and IdentityState bind receipt signatures to authenticated
	// operational-key epochs. Legacy v1/v2 homes leave both unset.
	BPlus         bool
	IdentityID    string
	IdentityState *identity.State

	receipts  []*Receipt
	petitions []Petition
	head      *string
	seq       int

	// PendingRecovery is true when an information-only open sees an unfinished
	// paired write. Read-only callers report it but never repair it silently.
	PendingRecovery bool
	// IdentityCreated is true only for the Open call that generated this
	// evidence home's first signing identity.
	IdentityCreated bool
}

// Open loads (and verifies) the ledger under home, creating a signing key on
// first use.
func Open(home string) (*Ledger, error) {
	if identity.IsBPlus(home) {
		return openBPlusSigning(home, true)
	}
	if err := os.MkdirAll(filepath.Join(home, "keys"), 0o700); err != nil {
		return nil, err
	}
	privatePath := filepath.Join(home, "keys", "ed25519_private.pem")
	publicPath := filepath.Join(home, "keys", "ed25519_public.pem")
	_, statErr := os.Lstat(privatePath)
	identityMissing := os.IsNotExist(statErr)
	if statErr != nil && !identityMissing {
		return nil, fmt.Errorf("ledger: inspect signing identity: %w", statErr)
	}
	pair, err := keys.LoadOrCreate(privatePath, publicPath)
	if err != nil {
		return nil, err
	}
	keyID, err := pair.KeyID()
	if err != nil {
		return nil, err
	}

	l := makeLedger(home, keyID, pair)
	l.IdentityCreated = identityMissing
	if err := recoverPendingFiles(l, pair); err != nil {
		return nil, err
	}
	if err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

// OpenExisting opens an existing ledger for an operation that may append. It
// never creates a new identity or completes a previously journaled pair.
func OpenExisting(home string) (*Ledger, error) {
	if pending, err := pendingExists(home); err != nil {
		return nil, err
	} else if pending {
		return nil, ErrRecoveryRequired
	}
	return openExisting(home, false)
}

// RecoverExisting explicitly completes a previously journaled receipt/petition
// pair before returning the verified signing ledger.
func RecoverExisting(home string) (*Ledger, error) {
	return openExisting(home, true)
}

func openExisting(home string, recoverReceiptWrite bool) (*Ledger, error) {
	if identity.IsBPlus(home) {
		return openBPlusSigning(home, recoverReceiptWrite)
	}
	pair, err := keys.LoadExisting(
		filepath.Join(home, "keys", "ed25519_private.pem"),
		filepath.Join(home, "keys", "ed25519_public.pem"),
	)
	if err != nil {
		return nil, err
	}
	keyID, err := pair.KeyID()
	if err != nil {
		return nil, err
	}
	l := makeLedger(home, keyID, pair)
	if recoverReceiptWrite {
		if err := recoverPendingFiles(l, pair); err != nil {
			return nil, err
		}
	}
	if err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

// OpenReadOnly opens existing evidence with the public key only. It does not
// create a home, load private key material, repair permissions, or recover a
// pending write.
func OpenReadOnly(home string) (*Ledger, error) {
	if identity.IsBPlus(home) {
		state, err := identity.LoadPublic(home)
		if err != nil {
			return nil, err
		}
		l := makeBPlusLedger(home, state)
		pending, err := pendingExists(home)
		if err != nil {
			return nil, fmt.Errorf("ledger: inspect recovery state: %w", err)
		}
		l.PendingRecovery = pending || state.PendingMutation
		if err := l.load(); err != nil {
			return nil, err
		}
		if result := VerifyBPlus(l.receipts, state); !result.OK {
			return nil, fmt.Errorf("ledger: B+ receipt authorization failed: %s", strings.Join(result.Findings, "; "))
		}
		return l, nil
	}
	pair, err := keys.LoadPublicFile(filepath.Join(home, "keys", "ed25519_public.pem"))
	if err != nil {
		return nil, err
	}
	keyID, err := pair.KeyID()
	if err != nil {
		return nil, err
	}
	l := makeLedger(home, keyID, pair)
	pending, err := pendingExists(home)
	if err != nil {
		return nil, fmt.Errorf("ledger: inspect recovery state: %w", err)
	}
	l.PendingRecovery = pending
	if err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

// OpenReadOnlyWithPrivate opens an existing ledger for a read-only operation
// that must sign derived output, such as export. It never performs recovery.
func OpenReadOnlyWithPrivate(home string) (*Ledger, error) {
	if identity.IsBPlus(home) {
		return openBPlusSigning(home, false)
	}
	pair, err := keys.LoadExisting(
		filepath.Join(home, "keys", "ed25519_private.pem"),
		filepath.Join(home, "keys", "ed25519_public.pem"),
	)
	if err != nil {
		return nil, err
	}
	keyID, err := pair.KeyID()
	if err != nil {
		return nil, err
	}
	l := makeLedger(home, keyID, pair)
	pending, err := pendingExists(home)
	if err != nil {
		return nil, fmt.Errorf("ledger: inspect recovery state: %w", err)
	}
	l.PendingRecovery = pending
	if err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

func openBPlusSigning(home string, recoverReceiptWrite bool) (*Ledger, error) {
	state, err := identity.LoadSigning(home)
	if err != nil {
		return nil, err
	}
	l := makeBPlusLedger(home, state)
	if recoverReceiptWrite {
		if err := recoverPendingFiles(l, state.ActivePair); err != nil {
			return nil, err
		}
	} else {
		pending, inspectErr := pendingExists(home)
		if inspectErr != nil {
			return nil, fmt.Errorf("ledger: inspect recovery state: %w", inspectErr)
		}
		l.PendingRecovery = pending
	}
	if err := l.load(); err != nil {
		return nil, err
	}
	if result := VerifyBPlus(l.receipts, state); !result.OK {
		return nil, fmt.Errorf("ledger: B+ receipt authorization failed: %s", strings.Join(result.Findings, "; "))
	}
	return l, nil
}

func makeBPlusLedger(home string, state *identity.State) *Ledger {
	l := makeLedger(home, "", nil)
	l.BPlus = true
	l.IdentityState = state
	if state != nil && state.Genesis != nil {
		l.IdentityID = state.Genesis.IdentityID
	}
	if state != nil && state.Active() != nil {
		l.KeyID = state.Active().OperationalKeyID
		if state.ActivePair != nil {
			l.Pair = state.ActivePair
		} else {
			l.Pair = state.Trust[l.KeyID]
		}
	}
	return l
}

func makeLedger(home, keyID string, pair *keys.Pair) *Ledger {
	return &Ledger{
		Home:          home,
		ReceiptsPath:  filepath.Join(home, "receipts.ndjson"),
		PetitionsPath: filepath.Join(home, "petitions.ndjson"),
		// The key id is derived from the key itself, so it cannot silently
		// name a different key than the one that signed.
		KeyID: keyID,
		Pair:  pair,
		seq:   -1,
	}
}

func (l *Ledger) load() error {
	l.receipts = nil
	l.petitions = nil
	l.head = nil
	l.seq = -1
	data, err := os.ReadFile(l.ReceiptsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		r, err := ParseReceiptStrict([]byte(line))
		if err != nil {
			return fmt.Errorf("ledger: corrupt receipt line: %w", err)
		}
		l.receipts = append(l.receipts, r)
	}
	if pdata, err := os.ReadFile(l.PetitionsPath); err == nil {
		for _, line := range strings.Split(string(pdata), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var p Petition
			if err := strictjson.Unmarshal([]byte(line), &p); err != nil {
				return fmt.Errorf("ledger: corrupt petition line: %w", err)
			}
			l.petitions = append(l.petitions, p)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("ledger: read stored requests: %w", err)
	}
	if n := len(l.receipts); n > 0 {
		last := l.receipts[n-1]
		id := last.ReceiptID
		l.head = &id
		l.seq = last.SequenceNo
	}
	return nil
}

// Receipts returns the loaded chain.
func (l *Ledger) Receipts() []*Receipt { return l.receipts }

// Petitions returns the loaded petitions.
func (l *Ledger) Petitions() []Petition { return l.petitions }

// Boundary returns the exact receipt-chain head used by lifecycle mutations.
func (l *Ledger) Boundary() identity.LedgerBoundary {
	boundary := identity.LedgerBoundary{SequenceNo: l.seq}
	if l.head != nil {
		id := *l.head
		boundary.ReceiptID = &id
	}
	return boundary
}

// PetitionByHash finds a stored petition by its hash.
func (l *Ledger) PetitionByHash(hash string) (Petition, bool) {
	for _, p := range l.petitions {
		if h, ok := p["petition_hash"].(string); ok && h == hash {
			return p, true
		}
	}
	return nil, false
}

// Append writes one receipt for a petition and returns it.
func (l *Ledger) Append(petition Petition, summary PetitionSummary, actor string, admission, expression, policyHash string, clauseIDs []string) (*Receipt, error) {
	if chain := l.VerifyReceipts(); !chain.OK {
		return nil, fmt.Errorf("ledger: refusing to append to an unverifiable receipt chain: %s", strings.Join(chain.Findings, "; "))
	}
	if l.BPlus {
		active := l.IdentityState.Active()
		if active == nil || active.Status != identity.StatusActive || l.Pair == nil || l.KeyID != active.OperationalKeyID {
			return nil, fmt.Errorf("ledger: B+ identity has no ACTIVE operational signing epoch")
		}
		if !sequenceAuthorized(active, l.seq+1) {
			return nil, fmt.Errorf("ledger: next receipt is outside the ACTIVE epoch authorization window")
		}
	}
	if bind := VerifyPetitions(l.receipts, l.petitions); !bind.OK {
		return nil, fmt.Errorf("ledger: refusing to append to evidence with missing or altered requests: %s", strings.Join(bind.Findings, "; "))
	}
	if clauseIDs == nil {
		clauseIDs = []string{}
	}

	// petition_hash binds the full request; the stored petition carries the
	// hash so a reader can re-derive it.
	body := map[string]any(petition)
	delete(body, "petition_hash")
	petitionHash, err := canon.HashJCS(body)
	if err != nil {
		return nil, fmt.Errorf("ledger: petition is not canonicalizable: %w", err)
	}

	clauses := make([]any, 0, len(clauseIDs))
	for _, c := range clauseIDs {
		clauses = append(clauses, c)
	}
	evaluationHash, err := canon.HashJCS(map[string]any{
		"clause_ids":     clauses,
		"engine_version": EngineVersion,
		"final_decision": admission,
		"petition_hash":  petitionHash,
		"policy_hash":    policyHash,
		"rule_results":   []any{},
	})
	if err != nil {
		return nil, err
	}

	r := &Receipt{
		PrevReceiptID:     l.head,
		SequenceNo:        l.seq + 1,
		TimestampISO8601:  time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00"),
		TimeSource:        "kernel_observed",
		Actor:             actor,
		AdapterDegraded:   false,
		PetitionHash:      petitionHash,
		PetitionSummary:   summary,
		AdmissionOutcome:  admission,
		ExpressionOutcome: expression,
		PolicyHash:        policyHash,
		EngineVersion:     EngineVersion,
		ClauseIDs:         clauseIDs,
		EvaluationHash:    evaluationHash,
		PassportRef:       nil,
		SigningKeyID:      l.KeyID,
	}

	id, err := r.ComputeID()
	if err != nil {
		return nil, err
	}
	r.ReceiptID = id
	sig, err := l.Pair.SignB64([]byte(id))
	if err != nil {
		return nil, err
	}
	r.SignatureB64 = sig

	petition["petition_hash"] = petitionHash
	petition["receipt_id"] = id

	receiptData, err := marshalSorted(r)
	if err != nil {
		return nil, err
	}
	petitionData, err := marshalSorted(petition)
	if err != nil {
		return nil, err
	}
	if err := beginPending(l.Home, receiptData, petitionData); err != nil {
		return nil, err
	}
	if err := appendBytes(l.ReceiptsPath, receiptData); err != nil {
		return nil, err
	}
	if err := appendBytes(l.PetitionsPath, petitionData); err != nil {
		return nil, err
	}
	if err := clearPending(l.Home); err != nil {
		return nil, err
	}

	l.receipts = append(l.receipts, r)
	l.petitions = append(l.petitions, petition)
	l.head = &id
	l.seq = r.SequenceNo
	return r, nil
}

// appendLine writes one JSON object per line with sorted keys, opened for
// append so concurrent writers cannot interleave partial records.
func appendLine(path string, v any) error {
	data, err := marshalSorted(v)
	if err != nil {
		return err
	}
	return appendBytes(path, data)
}

func appendBytes(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// marshalSorted produces compact JSON with sorted object keys, matching what
// the Python side writes so byte comparisons stay meaningful.
func marshalSorted(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(sortKeys(generic))
}

func sortKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = sortKeys(val)
		}
		return out
	case []any:
		for i := range t {
			t[i] = sortKeys(t[i])
		}
		return t
	}
	return v
}

// VerifyResult reports the state of a chain.
type VerifyResult struct {
	OK       bool     `json:"ok"`
	Checked  int      `json:"receipts_checked"`
	Findings []string `json:"findings"`
}

// Verify re-derives every receipt id, checks every signature against the
// trusted public keys, and walks the chain links. This is the check the old
// gateway never performed.
func Verify(receipts []*Receipt, trust map[string]*keys.Pair) VerifyResult {
	res := VerifyResult{OK: true, Findings: []string{}}
	seen := map[string]bool{}
	var prev *string

	for i, r := range receipts {
		where := fmt.Sprintf("sequence_no=%d", r.SequenceNo)

		if r.SequenceNo != i {
			res.fail(fmt.Sprintf("%s: out of order or missing receipt (expected %d)", where, i))
			return res
		}
		if !hex64.MatchString(r.ReceiptID) {
			res.fail(where + ": receipt_id is not 64 hex characters")
			return res
		}
		if seen[r.ReceiptID] {
			res.fail(where + ": duplicate receipt_id")
			return res
		}
		seen[r.ReceiptID] = true

		expected, err := r.ComputeID()
		if err != nil {
			res.fail(where + ": receipt is not canonicalizable: " + err.Error())
			return res
		}
		if expected != r.ReceiptID {
			res.fail(where + ": contents do not match receipt_id (receipt was modified after signing)")
			return res
		}

		pair, ok := trust[r.SigningKeyID]
		if !ok {
			res.fail(where + ": signing_key_id is not a trusted key: " + r.SigningKeyID)
			return res
		}
		if !pair.VerifyB64([]byte(r.ReceiptID), r.SignatureB64) {
			res.fail(where + ": signature does not verify")
			return res
		}

		if i == 0 {
			if r.PrevReceiptID != nil && *r.PrevReceiptID != "" {
				res.fail("first receipt must have a null prev_receipt_id")
				return res
			}
		} else {
			if r.PrevReceiptID == nil || prev == nil || *r.PrevReceiptID != *prev {
				res.fail(where + ": chain link does not match the previous receipt")
				return res
			}
		}
		id := r.ReceiptID
		prev = &id
		res.Checked++
	}
	return res
}

func (v *VerifyResult) fail(msg string) {
	v.OK = false
	v.Findings = append(v.Findings, msg)
}

// VerifyPetitions checks that each stored petition still hashes to the
// petition_hash its receipt recorded.
func VerifyPetitions(receipts []*Receipt, petitions []Petition) VerifyResult {
	res := VerifyResult{OK: true, Findings: []string{}}
	if len(receipts) != len(petitions) {
		res.fail(fmt.Sprintf("receipt/petition count mismatch: %d receipts, %d petitions", len(receipts), len(petitions)))
		return res
	}
	receiptByID := make(map[string]*Receipt, len(receipts))
	for _, receipt := range receipts {
		receiptByID[receipt.ReceiptID] = receipt
	}
	seenReceiptIDs := map[string]bool{}
	for _, p := range petitions {
		body := map[string]any{}
		for k, v := range p {
			if k == "petition_hash" || k == "receipt_id" {
				continue
			}
			body[k] = v
		}
		h, err := canon.HashJCS(normalizeNumbers(body))
		if err != nil {
			res.fail("petition is not canonicalizable: " + err.Error())
			return res
		}
		claimed, _ := p["petition_hash"].(string)
		if claimed != h {
			res.fail("petition contents do not match petition_hash " + short(claimed))
			return res
		}
		if claimed == "" {
			res.fail("missing petition_hash")
			return res
		}
		receiptID, _ := p["receipt_id"].(string)
		if receiptID == "" || seenReceiptIDs[receiptID] {
			res.fail("duplicate or missing petition receipt_id " + short(receiptID))
			return res
		}
		seenReceiptIDs[receiptID] = true
		receipt := receiptByID[receiptID]
		if receipt == nil {
			res.fail("orphan petition receipt_id " + short(receiptID))
			return res
		}
		if receipt.PetitionHash != claimed {
			res.fail(fmt.Sprintf("petition for receipt %s has hash %s, want %s", short(receiptID), short(claimed), short(receipt.PetitionHash)))
			return res
		}
		res.Checked++
	}
	return res
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// normalizeNumbers converts JSON numbers decoded as float64 back to int, since
// the canonical form forbids floats and UEG only ever records integers.
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalizeNumbers(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalizeNumbers(val)
		}
		return out
	case float64:
		return int64(t)
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return t.String()
		}
		return i
	}
	return v
}

// TrustSelf returns a trust map holding only this ledger's own key.
func (l *Ledger) TrustSelf() map[string]*keys.Pair {
	if l.BPlus && l.IdentityState != nil {
		trust := make(map[string]*keys.Pair, len(l.IdentityState.Trust)*2)
		for keyID, pair := range l.IdentityState.Trust {
			trust[keyID] = pair
			if legacy, err := pair.LegacyKeyID(); err == nil {
				trust[legacy] = pair
			}
		}
		return trust
	}
	trust := map[string]*keys.Pair{l.KeyID: l.Pair}
	if legacy, err := l.Pair.LegacyKeyID(); err == nil {
		trust[legacy] = l.Pair
	}
	return trust
}

// VerifyReceipts applies legacy signature/chain validation and, for B+ homes,
// the authenticated lifecycle authorization windows.
func (l *Ledger) VerifyReceipts() VerifyResult {
	if l.BPlus {
		return VerifyBPlus(l.receipts, l.IdentityState)
	}
	return Verify(l.receipts, l.TrustSelf())
}

// VerifyBPlus proves both mathematical receipt integrity and epoch authority.
func VerifyBPlus(receipts []*Receipt, state *identity.State) VerifyResult {
	if state == nil || state.Genesis == nil {
		return VerifyResult{OK: false, Findings: []string{"B+ lifecycle state is missing"}}
	}
	res := Verify(receipts, state.Trust)
	if !res.OK {
		return res
	}
	if err := verifyLifecycleBoundaries(receipts, state); err != nil {
		res.fail(err.Error())
		return res
	}
	epochByKey := map[string]*identity.EpochState{}
	for _, epoch := range state.Epochs {
		epochByKey[epoch.OperationalKeyID] = epoch
	}
	for _, receipt := range receipts {
		epoch := epochByKey[receipt.SigningKeyID]
		if epoch == nil {
			res.fail(fmt.Sprintf("sequence_no=%d: signing key is not an authenticated B+ epoch", receipt.SequenceNo))
			return res
		}
		if !sequenceAuthorized(epoch, receipt.SequenceNo) {
			res.fail(fmt.Sprintf("sequence_no=%d: signature is outside epoch %d's authorized ledger window", receipt.SequenceNo, epoch.EpochNumber))
			return res
		}
	}
	return res
}

func verifyLifecycleBoundaries(receipts []*Receipt, state *identity.State) error {
	for _, record := range state.Records {
		boundary := record.LedgerBoundary
		if boundary.SequenceNo == -1 {
			if boundary.ReceiptID != nil {
				return fmt.Errorf("lifecycle sequence %d has a receipt id at the empty-ledger boundary", record.LifecycleSequence)
			}
			continue
		}
		if boundary.SequenceNo < 0 || boundary.SequenceNo >= len(receipts) || boundary.ReceiptID == nil ||
			receipts[boundary.SequenceNo].ReceiptID != *boundary.ReceiptID {
			return fmt.Errorf("lifecycle sequence %d does not bind an exact receipt-chain boundary", record.LifecycleSequence)
		}
	}
	return nil
}

func sequenceAuthorized(epoch *identity.EpochState, sequence int) bool {
	for _, window := range epoch.Windows {
		if sequence <= window.StartAfter.SequenceNo {
			continue
		}
		if window.EndAt == nil || sequence <= window.EndAt.SequenceNo {
			return true
		}
	}
	return false
}
