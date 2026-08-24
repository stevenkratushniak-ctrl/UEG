// Package gateway is the execution path: a command enters, is classified,
// is admitted or refused, runs if admitted, and leaves signed evidence of
// exactly what happened.
package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
	"github.com/stevenkratushniak-ctrl/ueg/internal/policy"
)

// Stage is a position in the formation of a request. Stages only move forward
// and none of them is an error: a request that cannot proceed stops where it
// stopped, and the receipt says why.
type Stage int

const (
	VOID Stage = iota
	NASCENT
	DECLARED
	CANONICAL
	GATED
	EXECUTABLE
	EXECUTED
	STABILIZED
)

var stageNames = []string{"VOID", "NASCENT", "DECLARED", "CANONICAL", "GATED", "EXECUTABLE", "EXECUTED", "STABILIZED"}

// String returns the stage name.
func (s Stage) String() string {
	if int(s) < len(stageNames) {
		return stageNames[s]
	}
	return "UNKNOWN"
}

// Terminal reports whether no stage follows this one.
func (s Stage) Terminal() bool { return s == STABILIZED }

// Executable reports whether execution is permitted at this stage.
func (s Stage) Executable() bool { return s == EXECUTABLE }

// MaxExcerptBytes bounds how much captured output is written into the
// evidence. The SHA-256 always covers the whole stream.
const MaxExcerptBytes = 64 * 1024

// Options control one invocation.
type Options struct {
	Posture       policy.Posture
	Approvals     policy.Approvals
	DryRun        bool // classify and record, never execute (`ueg check`)
	SilentRefusal bool
	Stream        bool // copy child output to this process's stdout/stderr
	Cwd           string
}

// Result is what one invocation produced.
type Result struct {
	Stage            Stage                 `json:"stage"`
	Classification   policy.Classification `json:"classification"`
	Decision         policy.Decision       `json:"decision"`
	AdmissionReceipt *ledger.Receipt       `json:"admission_receipt"`
	OutcomeReceipt   *ledger.Receipt       `json:"outcome_receipt,omitempty"`
	Executed         bool                  `json:"executed"`
	ExitCode         int                   `json:"exit_code"`
	Stdout           string                `json:"-"`
	Stderr           string                `json:"-"`
	StdoutSHA256     string                `json:"stdout_sha256,omitempty"`
	StderrSHA256     string                `json:"stderr_sha256,omitempty"`
	StdoutBytes      int64                 `json:"stdout_bytes,omitempty"`
	StderrBytes      int64                 `json:"stderr_bytes,omitempty"`
	StdoutTruncated  bool                  `json:"stdout_truncated,omitempty"`
	StderrTruncated  bool                  `json:"stderr_truncated,omitempty"`
	DurationMs       int64                 `json:"duration_ms,omitempty"`
	Path             []string              `json:"stage_path"`
}

// Actor identifies who asked, for the receipt.
func Actor() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("ueg:cli:%s@%s", name, host)
}

// Run takes a command through the gateway.
func Run(l *ledger.Ledger, argv []string, opts Options) (*Result, error) {
	res := &Result{Stage: VOID, ExitCode: 0}
	advance := func(s Stage) {
		res.Stage = s
		res.Path = append(res.Path, s.String())
	}
	advance(NASCENT)

	if len(argv) == 0 {
		return res, fmt.Errorf("no command given")
	}

	cwd := opts.Cwd
	if cwd == "" {
		if wd, err := os.Getwd(); err == nil {
			cwd = wd
		}
	}

	// DECLARED: the command has an identity on this machine.
	resolved, lookErr := exec.LookPath(argv[0])
	if lookErr != nil {
		resolved = argv[0]
	}
	advance(DECLARED)

	// CANONICAL: one exact command line, no ambiguity left.
	canonicalArgv := append([]string{}, argv...)
	target := strings.Join(canonicalArgv, " ")
	advance(CANONICAL)

	// GATED: the effect is named before anything happens.
	class := policy.Classify(canonicalArgv)
	res.Classification = class
	advance(GATED)

	decision := policy.Decide(class, opts.Posture, opts.Approvals)
	res.Decision = decision

	policyHash := policy.Hash(opts.Posture, opts.Approvals)
	actor := Actor()

	admissionPetition := ledger.Petition{
		"action":           "execute",
		"argv":             toAnySlice(canonicalArgv),
		"cwd":              cwd,
		"decision":         string(decision.Outcome),
		"decision_reason":  decision.Reason,
		"approval":         decision.Approval,
		"effect_class":     string(class.Class),
		"elevated":         class.Elevated,
		"engine_version":   ledger.EngineVersion,
		"executed":         false,
		"host_arch":        runtime.GOARCH,
		"host_os":          runtime.GOOS,
		"policy_hash":      policyHash,
		"posture":          string(opts.Posture),
		"resolved_path":    resolved,
		"resolution_error": errString(lookErr),
		"rule_id":          class.RuleID,
		"rule_note":        class.Reason,
		"surface":          class.Surface,
		"target":           target,
		"dry_run":          opts.DryRun,
	}

	willExecute := decision.Outcome == policy.Admitted && !opts.DryRun
	admissionPetition["executed"] = willExecute

	expression := "SILENT"
	if willExecute {
		expression = "EXPRESSED"
	}

	summary := ledger.PetitionSummary{
		Surface: class.Surface,
		Action:  "execute",
		Target:  target,
	}

	admission, err := l.Append(admissionPetition, summary, actor, string(decision.Outcome), expression, policyHash, []string{class.RuleID})
	if err != nil {
		return res, err
	}
	res.AdmissionReceipt = admission

	if !willExecute {
		// The request stops at GATED. It never became executable, so there is
		// nothing to undo and nothing to prove beyond the refusal itself.
		if decision.Outcome == policy.Refused {
			res.ExitCode = 77
		}
		return res, nil
	}

	// EXECUTABLE: and only here.
	advance(EXECUTABLE)
	if !res.Stage.Executable() {
		return res, fmt.Errorf("internal: execution attempted from stage %s", res.Stage)
	}

	stdout, stderr, exitCode, duration := execute(resolved, canonicalArgv, cwd, opts.Stream)
	advance(EXECUTED)

	res.Executed = true
	res.ExitCode = exitCode
	res.Stdout = stdout.Excerpt
	res.Stderr = stderr.Excerpt
	res.StdoutSHA256 = stdout.SHA256
	res.StderrSHA256 = stderr.SHA256
	res.StdoutBytes = stdout.Bytes
	res.StderrBytes = stderr.Bytes
	res.StdoutTruncated = stdout.Truncated
	res.StderrTruncated = stderr.Truncated
	res.DurationMs = duration

	outcomePetition := ledger.Petition{
		"action":               "record-outcome",
		"admission_receipt_id": admission.ReceiptID,
		"argv":                 toAnySlice(canonicalArgv),
		"cwd":                  cwd,
		"duration_ms":          duration,
		"engine_version":       ledger.EngineVersion,
		"exit_code":            int64(exitCode),
		"host_arch":            runtime.GOARCH,
		"host_os":              runtime.GOOS,
		"policy_hash":          policyHash,
		"stderr_bytes":         stderr.Bytes,
		"stderr_excerpt":       stderr.Excerpt,
		"stderr_sha256":        res.StderrSHA256,
		"stderr_truncated":     stderr.Truncated,
		"stdout_bytes":         stdout.Bytes,
		"stdout_excerpt":       stdout.Excerpt,
		"stdout_sha256":        res.StdoutSHA256,
		"stdout_truncated":     stdout.Truncated,
		"surface":              class.Surface,
		"target":               target,
	}

	outcome, err := l.Append(outcomePetition, ledger.PetitionSummary{
		Surface: class.Surface,
		Action:  "record-outcome",
		Target:  target,
	}, actor, "ADMITTED", "EXPRESSED", policyHash, []string{"outcome"})
	if err != nil {
		return res, err
	}
	res.OutcomeReceipt = outcome
	advance(STABILIZED)
	return res, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func toAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

type capturedOutput struct {
	Excerpt   string
	SHA256    string
	Bytes     int64
	Truncated bool
}

type outputCapture struct {
	digest  hash.Hash
	excerpt []byte
	bytes   int64
	mirror  io.Writer
}

func newOutputCapture(mirror io.Writer) *outputCapture {
	return &outputCapture{
		digest:  sha256.New(),
		excerpt: make([]byte, 0, MaxExcerptBytes),
		mirror:  mirror,
	}
}

func (c *outputCapture) Write(p []byte) (int, error) {
	c.bytes += int64(len(p))
	_, _ = c.digest.Write(p)
	if remaining := MaxExcerptBytes - len(c.excerpt); remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		c.excerpt = append(c.excerpt, p[:remaining]...)
	}
	if c.mirror != nil {
		n, err := c.mirror.Write(p)
		if err != nil {
			return n, err
		}
		if n != len(p) {
			return n, io.ErrShortWrite
		}
	}
	return len(p), nil
}

func (c *outputCapture) result() capturedOutput {
	return capturedOutput{
		Excerpt:   string(c.excerpt),
		SHA256:    hex.EncodeToString(c.digest.Sum(nil)),
		Bytes:     c.bytes,
		Truncated: c.bytes > int64(len(c.excerpt)),
	}
}

// execute runs the recorded executable path, retaining only bounded excerpts
// while hashing and counting both complete output streams.
func execute(resolved string, argv []string, cwd string, stream bool) (capturedOutput, capturedOutput, int, int64) {
	start := time.Now()

	cmd := exec.Command(resolved, argv[1:]...)
	cmd.Args[0] = argv[0]
	cmd.Dir = cwd

	var stdoutMirror, stderrMirror io.Writer
	if stream {
		stdoutMirror = os.Stdout
		stderrMirror = os.Stderr
	}
	outCapture := newOutputCapture(stdoutMirror)
	errCapture := newOutputCapture(stderrMirror)
	cmd.Stdout = outCapture
	cmd.Stderr = errCapture
	cmd.Stdin = os.Stdin

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 127
			_, _ = errCapture.Write([]byte(err.Error() + "\n"))
		}
	}

	return outCapture.result(), errCapture.result(), exitCode, time.Since(start).Milliseconds()
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

// DefaultHome is where the ledger and keys live.
func DefaultHome() string {
	if h := os.Getenv("UEG_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ueg"
	}
	return filepath.Join(home, ".ueg")
}
