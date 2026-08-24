package gateway

import (
	"fmt"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
	"github.com/stevenkratushniak-ctrl/ueg/internal/policy"
)

// ReplayVerdict is the outcome of replaying a recorded run.
type ReplayVerdict string

const (
	// Tampered: the stored evidence failed verification, so nothing was replayed.
	Tampered ReplayVerdict = "TAMPERED"
	// Match: the command produced the same exit code and the same output bytes.
	Match ReplayVerdict = "MATCH"
	// Diverged: verified evidence, different result.
	Diverged ReplayVerdict = "DIVERGED"
	// Refused: the replay itself was refused (effect too dangerous to repeat).
	RefusedReplay ReplayVerdict = "REFUSED"
	// RefusalConfirmed: the recorded run was refused and is still refused.
	RefusalConfirmed ReplayVerdict = "REFUSAL_CONFIRMED"
	// CheckConfirmed: a recorded check still reaches the same classification and decision.
	CheckConfirmed ReplayVerdict = "CHECK_CONFIRMED"
	// Incomplete: the signed admission is intact but no signed outcome exists.
	Incomplete ReplayVerdict = "INCOMPLETE_OR_TRUNCATED"
)

// ReplayResult describes what replay found.
type ReplayResult struct {
	Verdict                  ReplayVerdict  `json:"verdict"`
	Reason                   string         `json:"reason"`
	Differences              []string       `json:"differences"`
	ChainOK                  bool           `json:"chain_ok"`
	ChainFindings            []string       `json:"chain_findings"`
	Target                   string         `json:"target"`
	Recorded                 map[string]any `json:"recorded,omitempty"`
	Observed                 map[string]any `json:"observed,omitempty"`
	ReplayAdmissionReceiptID string         `json:"replay_admission_receipt_id,omitempty"`
	ReplayOutcomeReceiptID   string         `json:"replay_outcome_receipt_id,omitempty"`
	LifecycleFreshness       string         `json:"lifecycle_freshness,omitempty"`
}

// Replay re-runs a recorded command and compares the result against the
// signed evidence — after proving the evidence has not been altered.
//
// Verification comes first and is not optional: a modified receipt is reported
// as TAMPERED and nothing is executed.
func Replay(l *ledger.Ledger, selector string, opts Options) (*ReplayResult, error) {
	res := &ReplayResult{Differences: []string{}, ChainFindings: []string{}}

	chain := l.VerifyReceipts()
	bind := ledger.VerifyPetitions(l.Receipts(), l.Petitions())
	res.ChainOK = chain.OK && bind.OK
	res.ChainFindings = append(append([]string{}, chain.Findings...), bind.Findings...)
	if !res.ChainOK {
		res.Verdict = Tampered
		res.Reason = "stored evidence failed verification; nothing was replayed"
		return res, nil
	}

	admission, err := findAdmission(l, selector)
	if err != nil {
		return nil, err
	}
	res.Target, _ = admission["target"].(string)

	argv := toStringSlice(admission["argv"])
	cwd, _ := admission["cwd"].(string)
	recordedDecision, _ := admission["decision"].(string)
	recordedClass, _ := admission["effect_class"].(string)
	recordedPosture, _ := admission["posture"].(string)
	executed, _ := admission["executed"].(bool)
	dryRun, _ := admission["dry_run"].(bool)

	res.Recorded = map[string]any{
		"decision":     recordedDecision,
		"effect_class": recordedClass,
		"posture":      recordedPosture,
		"executed":     executed,
	}

	// A check or refusal has no output to reproduce. Re-enter the normal
	// gateway as a check only, so a later policy change can never turn a
	// refusal-confirmation request into an execution.
	if !executed {
		if !dryRun && recordedDecision != string(policy.Refused) {
			res.Verdict = Incomplete
			res.Reason = "the record says execution was admitted but contains no completed execution; it may be interrupted or terminal evidence may be missing, and nothing was replayed"
			return res, nil
		}
		approvals := policy.Approvals{
			Irrevocable:  boolField(admission, "approval") == "operator",
			Unclassified: boolField(admission, "approval") == "operator-unclassified",
		}
		observed, runErr := Run(l, argv, Options{
			Posture:   policy.Posture(recordedPosture),
			Approvals: approvals,
			DryRun:    true,
			Cwd:       cwd,
		})
		if runErr != nil {
			return nil, runErr
		}
		res.ReplayAdmissionReceiptID = receiptID(observed.AdmissionReceipt)
		res.ReplayOutcomeReceiptID = receiptID(observed.OutcomeReceipt)
		res.Observed = map[string]any{
			"decision":     string(observed.Decision.Outcome),
			"effect_class": string(observed.Classification.Class),
		}
		if string(observed.Decision.Outcome) == recordedDecision && string(observed.Classification.Class) == recordedClass {
			if dryRun {
				res.Verdict = CheckConfirmed
				res.Reason = "the recorded check and the current check reach the same classification and decision"
			} else {
				res.Verdict = RefusalConfirmed
				res.Reason = fmt.Sprintf("not executed when recorded (%s); current rules reach the same refusal", recordedDecision)
			}
			return res, nil
		}
		res.Verdict = Diverged
		if string(observed.Classification.Class) != recordedClass {
			res.Differences = append(res.Differences, fmt.Sprintf("effect_class: recorded %s, now %s", recordedClass, observed.Classification.Class))
		}
		if string(observed.Decision.Outcome) != recordedDecision {
			res.Differences = append(res.Differences, fmt.Sprintf("decision: recorded %s, now %s", recordedDecision, observed.Decision.Outcome))
		}
		res.Reason = "the rule table no longer reaches the recorded decision"
		return res, nil
	}

	outcome, ok := findOutcome(l, admission)
	if !ok {
		res.Verdict = Incomplete
		res.Reason = "the admission is intact but no outcome exists; the process may have been interrupted or terminal evidence may have been removed, and nothing was replayed"
		return res, nil
	}

	// Replaying is another real execution. It goes through the current enforce
	// gate and leaves its own signed evidence; observe posture cannot weaken it.
	opts.Posture = policy.Enforce
	opts.Cwd = cwd
	opts.Stream = false
	observed, runErr := Run(l, argv, opts)
	if runErr != nil {
		return nil, runErr
	}
	res.ReplayAdmissionReceiptID = receiptID(observed.AdmissionReceipt)
	res.ReplayOutcomeReceiptID = receiptID(observed.OutcomeReceipt)
	if !observed.Executed {
		res.Verdict = RefusedReplay
		res.Reason = "the current enforce policy refused this replay: " + observed.Decision.Reason
		return res, nil
	}

	obsOut := observed.StdoutSHA256
	obsErr := observed.StderrSHA256

	recExit := intField(outcome, "exit_code")
	recOut, _ := outcome["stdout_sha256"].(string)
	recErr, _ := outcome["stderr_sha256"].(string)

	res.Recorded["exit_code"] = recExit
	res.Recorded["stdout_sha256"] = recOut
	res.Recorded["stderr_sha256"] = recErr
	res.Observed = map[string]any{
		"exit_code":     int64(observed.ExitCode),
		"stdout_sha256": obsOut,
		"stderr_sha256": obsErr,
	}

	if int64(observed.ExitCode) != recExit {
		res.Differences = append(res.Differences, fmt.Sprintf("exit_code: recorded %d, observed %d", recExit, observed.ExitCode))
	}
	if obsOut != recOut {
		res.Differences = append(res.Differences, fmt.Sprintf("stdout: recorded sha256 %s, observed %s", shortHash(recOut), shortHash(obsOut)))
	}
	if obsErr != recErr {
		res.Differences = append(res.Differences, fmt.Sprintf("stderr: recorded sha256 %s, observed %s", shortHash(recErr), shortHash(obsErr)))
	}

	if len(res.Differences) == 0 {
		res.Verdict = Match
		res.Reason = "signatures verified, and the command reproduced the recorded exit code and output bytes"
	} else {
		res.Verdict = Diverged
		res.Reason = "signatures verified, but the command did not reproduce what was recorded"
	}
	return res, nil
}

func receiptID(receipt *ledger.Receipt) string {
	if receipt == nil {
		return ""
	}
	return receipt.ReceiptID
}

func findAdmission(l *ledger.Ledger, selector string) (ledger.Petition, error) {
	sel := strings.TrimSpace(selector)
	var matches []ledger.Petition
	for _, p := range l.Petitions() {
		if action, _ := p["action"].(string); action != "execute" {
			continue
		}
		rid, _ := p["receipt_id"].(string)
		ph, _ := p["petition_hash"].(string)
		if sel == "" || sel == "last" {
			matches = append(matches, p)
			continue
		}
		if strings.HasPrefix(rid, sel) || strings.HasPrefix(ph, sel) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no recorded run matches %q", selector)
	}
	if sel == "" || sel == "last" {
		return matches[len(matches)-1], nil
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("%q matches %d runs; use more characters of the receipt id", selector, len(matches))
	}
	return matches[0], nil
}

func findOutcome(l *ledger.Ledger, admission ledger.Petition) (ledger.Petition, bool) {
	rid, _ := admission["receipt_id"].(string)
	for _, p := range l.Petitions() {
		if action, _ := p["action"].(string); action != "record-outcome" {
			continue
		}
		if ref, _ := p["admission_receipt_id"].(string); ref == rid {
			return p, true
		}
	}
	return nil, false
}

func toStringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

func intField(p ledger.Petition, key string) int64 {
	switch t := p[key].(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	}
	return 0
}

func boolField(p ledger.Petition, key string) string {
	s, _ := p[key].(string)
	return s
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
