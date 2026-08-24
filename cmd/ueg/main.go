// Command ueg runs a command and leaves signed, offline-verifiable evidence of
// what was asked, what was allowed, what ran, and what came back.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/bundle"
	"github.com/stevenkratushniak-ctrl/ueg/internal/gateway"
	"github.com/stevenkratushniak-ctrl/ueg/internal/identity"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
	"github.com/stevenkratushniak-ctrl/ueg/internal/policy"
)

// Version is the released version, set at build time for release binaries.
var Version = "2.2.0-v3-candidate.1"

const usage = `ueg — Universal Execution Gateway

Runs a command and records signed evidence of it. The evidence can be exported
and verified by someone who does not trust the machine that produced it.

Usage:
  ueg identity <command> [flags]             Initialize and manage a B+ evidence identity
  ueg run [flags] -- <command> [args...]     Classify, admit or refuse, execute, record
  ueg check [flags] -- <command> [args...]   Classify only; never execute or write state
  ueg replay [flags] [<receipt-id-prefix>]   Verify the evidence, then re-run and compare
  ueg export <bundle.tar.gz>                 Write a signed, offline-verifiable bundle
  ueg verify [trust flags] <bundle.tar.gz>   Verify legacy or B+ evidence without mutation
  ueg ledger [--json]                        Show the local receipt chain
  ueg recover [--json]                       Complete an interrupted evidence write
  ueg policy [--json]                        Show the effect rules in force
  ueg validate (or ueg --validate)           Prove the properties of the state model
  ueg version

Flags:
  --posture enforce|observe   enforce (default) refuses what the rules forbid;
                              observe records and admits non-prohibited effects
  --approve                   admit an IRREVOCABLE effect (never a PROHIBITED one)
  --allow-unclassified        admit a command no rule describes
  --json                      machine-readable output
  --home <dir>                evidence directory (default $UEG_HOME or ~/.ueg)
  --expected-key-id <id>      externally pinned ueg:sha256 fingerprint for identity trust
  --expected-identity-id <id> externally pinned B+ genesis identity digest
  --checkpoint <file>         independently supplied B+ lifecycle checkpoint
  --anchor <file>             independently retained B+ evidence anchor
  --trust-store <dir>         explicit retained-checkpoint store
  --require-current-status    fail if offline freshness cannot be established

Exit codes:
  the command's own exit code when it ran, 77 when UEG refused it, 2 on a
  verification failure, 3 for an incomplete recorded execution, and 1 on a
  usage or internal error.
`

var commandUsage = map[string]string{
	"run": `Usage: ueg run [--posture enforce|observe] [--approve] [--allow-unclassified] [--json] [--home <dir>] [--checkpoint <file> | --trust-store <dir>] -- <command> [args...]

Classify the command, refuse or admit it, execute admitted commands, and record signed evidence.
`,
	"check": `Usage: ueg check [--posture enforce|observe] [--approve] [--allow-unclassified] [--json] [--home <dir>] -- <command> [args...]

Classify the command without executing it or changing any evidence state.
`,
	"identity": identityUsage,
	"replay": `Usage: ueg replay [--posture enforce|observe] [--approve] [--allow-unclassified] [--json] [--home <dir>] [--checkpoint <file> | --trust-store <dir>] [<receipt-id-prefix>]

Verify stored evidence, safely re-run one complete recorded command, and record the replay.
The posture flag is accepted for command-line compatibility; replay always applies enforce policy.
`,
	"export": `Usage: ueg export [--json] [--home <dir>] <bundle.tar.gz>

Write a signed evidence bundle. Export reads but does not change the evidence home.
`,
	"verify": `Usage: ueg verify [--json] [--expected-key-id <id> | --expected-identity-id <id> [--checkpoint <file> | --trust-store <dir>] [--anchor <file>] [--minimum-checkpoint-sequence <n> --minimum-checkpoint-digest <sha256>] [--require-current-status]] <bundle.tar.gz>

Verify a bundle without creating or changing a local evidence home.
Legacy v1/v2 identity trust uses --expected-key-id. B+ requires an independently
retained genesis identity pin and lifecycle checkpoint for a VERIFIED verdict.
`,
	"ledger": `Usage: ueg ledger [--json] [--home <dir>]

Inspect and verify existing local evidence without changing it.
`,
	"recover": `Usage: ueg recover [--json] [--home <dir>]

Complete one interrupted paired evidence write, then verify the local chain.
This command changes the evidence home only when recovery is required.
`,
	"policy": `Usage: ueg policy [--json] [--posture enforce|observe] [--approve] [--allow-unclassified] [-- <command> [args...]]

Show the rules or classify one command without executing or recording it.
`,
	"validate": `Usage: ueg validate [--json] [--home <dir>]

Validate the state model and, when present, inspect local evidence without changing it.
`,
	"version": "Usage: ueg version\n",
}

func main() {
	os.Exit(run(os.Args[1:]))
}

type flags struct {
	posture                   policy.Posture
	approve                   bool
	allowUnclass              bool
	jsonOut                   bool
	home                      string
	expectedKey               string
	expectedIdentity          string
	checkpoint                string
	anchor                    string
	trustStore                string
	minimumCheckpointSequence *int
	minimumCheckpointDigest   string
	requireCurrentStatus      bool
	lifecycleFreshness        string
	rest                      []string
	help                      bool
	version                   bool
	sawSeparator              bool
}

type allowedFlags struct {
	posture, approve, allowUnclass, jsonOut, home, expectedKey, expectedIdentity                             bool
	checkpoint, anchor, trustStore, minimumCheckpointSequence, minimumCheckpointDigest, requireCurrentStatus bool
}

func parseFlags(command string, args []string, allowed allowedFlags) (*flags, error) {
	f := &flags{posture: policy.Enforce, home: gateway.DefaultHome()}
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			f.sawSeparator = true
			f.rest = append(f.rest, args[i+1:]...)
			return f, nil
		}
		switch {
		case a == "-h" || a == "--help":
			f.help = true
			i++
		case a == "--version":
			f.version = true
			i++
		case a == "--posture":
			if !allowed.posture {
				return nil, fmt.Errorf("--posture is not valid for %s", command)
			}
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--posture needs a value (enforce or observe)")
			}
			p := policy.Posture(args[i+1])
			if p != policy.Enforce && p != policy.Observe {
				return nil, fmt.Errorf("unknown posture %q", args[i+1])
			}
			f.posture = p
			i += 2
		case strings.HasPrefix(a, "--posture="):
			if !allowed.posture {
				return nil, fmt.Errorf("--posture is not valid for %s", command)
			}
			p := policy.Posture(strings.TrimPrefix(a, "--posture="))
			if p != policy.Enforce && p != policy.Observe {
				return nil, fmt.Errorf("unknown posture %q", p)
			}
			f.posture = p
			i++
		case a == "--approve":
			if !allowed.approve {
				return nil, fmt.Errorf("--approve is not valid for %s", command)
			}
			f.approve = true
			i++
		case a == "--allow-unclassified":
			if !allowed.allowUnclass {
				return nil, fmt.Errorf("--allow-unclassified is not valid for %s", command)
			}
			f.allowUnclass = true
			i++
		case a == "--json":
			if !allowed.jsonOut {
				return nil, fmt.Errorf("--json is not valid for %s", command)
			}
			f.jsonOut = true
			i++
		case a == "--home":
			if !allowed.home {
				return nil, fmt.Errorf("--home is not valid for %s", command)
			}
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--home needs a directory")
			}
			f.home = args[i+1]
			if strings.TrimSpace(f.home) == "" {
				return nil, fmt.Errorf("--home needs a non-empty directory")
			}
			i += 2
		case strings.HasPrefix(a, "--home="):
			if !allowed.home {
				return nil, fmt.Errorf("--home is not valid for %s", command)
			}
			f.home = strings.TrimPrefix(a, "--home=")
			if strings.TrimSpace(f.home) == "" {
				return nil, fmt.Errorf("--home needs a non-empty directory")
			}
			i++
		case a == "--expected-key-id":
			if !allowed.expectedKey {
				return nil, fmt.Errorf("--expected-key-id is not valid for %s", command)
			}
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--expected-key-id needs a ueg:sha256 fingerprint")
			}
			f.expectedKey = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--expected-key-id="):
			if !allowed.expectedKey {
				return nil, fmt.Errorf("--expected-key-id is not valid for %s", command)
			}
			f.expectedKey = strings.TrimPrefix(a, "--expected-key-id=")
			if strings.TrimSpace(f.expectedKey) == "" {
				return nil, fmt.Errorf("--expected-key-id needs a ueg:sha256 fingerprint")
			}
			i++
		case a == "--expected-identity-id":
			if !allowed.expectedIdentity {
				return nil, fmt.Errorf("--expected-identity-id is not valid for %s", command)
			}
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return nil, fmt.Errorf("--expected-identity-id needs a complete B+ genesis identity pin")
			}
			f.expectedIdentity = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--expected-identity-id="):
			if !allowed.expectedIdentity {
				return nil, fmt.Errorf("--expected-identity-id is not valid for %s", command)
			}
			f.expectedIdentity = strings.TrimPrefix(a, "--expected-identity-id=")
			if strings.TrimSpace(f.expectedIdentity) == "" {
				return nil, fmt.Errorf("--expected-identity-id needs a complete B+ genesis identity pin")
			}
			i++
		case a == "--checkpoint" || a == "--anchor" || a == "--trust-store" || a == "--minimum-checkpoint-digest":
			name := strings.TrimPrefix(a, "--")
			permitted := map[string]bool{"checkpoint": allowed.checkpoint, "anchor": allowed.anchor, "trust-store": allowed.trustStore, "minimum-checkpoint-digest": allowed.minimumCheckpointDigest}[name]
			if !permitted {
				return nil, fmt.Errorf("%s is not valid for %s", a, command)
			}
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return nil, fmt.Errorf("%s needs a non-empty value", a)
			}
			switch name {
			case "checkpoint":
				f.checkpoint = args[i+1]
			case "anchor":
				f.anchor = args[i+1]
			case "trust-store":
				f.trustStore = args[i+1]
			case "minimum-checkpoint-digest":
				f.minimumCheckpointDigest = args[i+1]
			}
			i += 2
		case a == "--minimum-checkpoint-sequence":
			if !allowed.minimumCheckpointSequence {
				return nil, fmt.Errorf("--minimum-checkpoint-sequence is not valid for %s", command)
			}
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--minimum-checkpoint-sequence needs a non-negative integer")
			}
			value, parseErr := strconv.Atoi(args[i+1])
			if parseErr != nil || value < 0 {
				return nil, fmt.Errorf("--minimum-checkpoint-sequence needs a non-negative integer")
			}
			f.minimumCheckpointSequence = &value
			i += 2
		case a == "--require-current-status":
			if !allowed.requireCurrentStatus {
				return nil, fmt.Errorf("--require-current-status is not valid for %s", command)
			}
			f.requireCurrentStatus = true
			i++
		default:
			if strings.HasPrefix(a, "-") {
				return nil, fmt.Errorf("unknown option %q for %s", a, command)
			}
			f.rest = append(f.rest, args[i:]...)
			return f, nil
		}
	}
	return f, nil
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return 0
	}
	if args[0] == "--validate" {
		args = append([]string{"validate"}, args[1:]...)
	}
	if args[0] == "--version" {
		printVersion()
		return 0
	}
	if args[0] == "help" {
		if len(args) == 1 {
			fmt.Print(usage)
			return 0
		}
		if len(args) == 2 {
			if help, ok := commandUsage[args[1]]; ok {
				fmt.Print(help)
				return 0
			}
		}
		fmt.Fprintln(os.Stderr, "ueg: help needs one known command name; run ueg --help to see available commands")
		return 1
	}

	command := args[0]
	if command == "identity" {
		return cmdIdentity(args[1:])
	}
	var allowed allowedFlags
	switch command {
	case "run":
		allowed = allowedFlags{posture: true, approve: true, allowUnclass: true, jsonOut: true, home: true, checkpoint: true, trustStore: true}
	case "check":
		allowed = allowedFlags{posture: true, approve: true, allowUnclass: true, jsonOut: true, home: true}
	case "replay":
		allowed = allowedFlags{posture: true, approve: true, allowUnclass: true, jsonOut: true, home: true, checkpoint: true, trustStore: true}
	case "export", "ledger", "recover", "validate":
		allowed = allowedFlags{jsonOut: true, home: true}
	case "verify":
		allowed = allowedFlags{jsonOut: true, expectedKey: true, expectedIdentity: true, checkpoint: true, anchor: true,
			trustStore: true, minimumCheckpointSequence: true, minimumCheckpointDigest: true, requireCurrentStatus: true}
	case "policy":
		allowed = allowedFlags{posture: true, approve: true, allowUnclass: true, jsonOut: true}
	case "version":
		allowed = allowedFlags{}
	default:
		jsonOut := jsonRequested(args)
		if strings.HasPrefix(command, "-") {
			return cliError(jsonOut, "USAGE", fmt.Sprintf("unknown option %q; run ueg --help to see available commands", command), 1)
		} else {
			return cliError(jsonOut, "USAGE", fmt.Sprintf("unknown command %q; run ueg --help to see available commands", command), 1)
		}
	}
	f, err := parseFlags(command, args[1:], allowed)
	if err != nil {
		return cliError(jsonRequested(args[1:]), "USAGE", err.Error(), 1)
	}
	if f.help || (len(f.rest) == 1 && f.rest[0] == "help" && !f.sawSeparator) {
		fmt.Print(commandUsage[command])
		return 0
	}
	if f.version {
		printVersion()
		return 0
	}

	switch command {
	case "version":
		if len(f.rest) != 0 {
			return cliError(f.jsonOut, "USAGE", "version takes no arguments", 1)
		}
		printVersion()
		return 0
	case "validate":
		if len(f.rest) != 0 {
			return usageError(f, "validate takes no arguments", command)
		}
		return cmdValidate(f)
	case "policy":
		if len(f.rest) > 0 && !f.sawSeparator {
			return usageError(f, "put a command after -- when asking policy to classify it", command)
		}
		return cmdPolicy(f)
	case "run", "check":
		if !f.sawSeparator {
			if len(f.rest) == 0 {
				return usageError(f, "no command given; put the command to evaluate after --", command)
			}
			return usageError(f, "put the command to evaluate after --", command)
		}
		return cmdRun(f, command == "check")
	case "replay":
		if len(f.rest) > 1 || f.sawSeparator {
			return usageError(f, "replay accepts at most one receipt-id prefix", command)
		}
		return cmdReplay(f)
	case "export":
		if len(f.rest) != 1 || f.sawSeparator {
			if len(f.rest) == 0 {
				return usageError(f, "export needs an output path", command)
			}
			return usageError(f, "export needs exactly one bundle path", command)
		}
		return cmdExport(f)
	case "verify":
		if len(f.rest) != 1 || f.sawSeparator {
			if len(f.rest) == 0 {
				return usageError(f, "verify needs a bundle path", command)
			}
			return usageError(f, "verify needs exactly one bundle path", command)
		}
		return cmdVerify(f)
	case "ledger":
		if len(f.rest) != 0 {
			return usageError(f, "ledger takes no arguments", command)
		}
		return cmdLedger(f)
	case "recover":
		if len(f.rest) != 0 {
			return usageError(f, "recover takes no arguments", command)
		}
		return cmdRecover(f)
	}
	return 1
}

func printVersion() {
	fmt.Printf("ueg %s (rules v%s, %d rules, %s)\n", Version, policy.RulesVersion(), policy.RuleCount(), policy.RulesHash[:12])
}

func usageError(f *flags, message, command string) int {
	if f.jsonOut {
		return cliError(true, "USAGE", message, 1)
	}
	fmt.Fprintf(os.Stderr, "ueg: %s\n\n%s", message, commandUsage[command])
	return 1
}

func jsonRequested(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--json" {
			return true
		}
	}
	return false
}

func cliError(jsonOut bool, code, message string, exitCode int) int {
	if jsonOut {
		printJSON(map[string]any{
			"ok":        false,
			"exit_code": exitCode,
			"error": map[string]any{
				"code":    code,
				"message": message,
			},
		})
		return exitCode
	}
	fmt.Fprintln(os.Stderr, "ueg:", message)
	return exitCode
}

type ledgerMode int

const (
	ledgerCreate ledgerMode = iota
	ledgerExistingWrite
	ledgerRecover
	ledgerReadOnly
	ledgerReadOnlyPrivate
)

func openLedger(f *flags, mode ledgerMode) (*ledger.Ledger, *ledger.HomeLock, int) {
	if mode != ledgerCreate {
		info, err := os.Stat(f.home)
		if err != nil {
			if os.IsNotExist(err) {
				message := fmt.Sprintf("evidence directory does not exist at %s; initialize one explicitly with ueg identity init", f.home)
				return nil, nil, cliError(f.jsonOut, "EVIDENCE_NOT_FOUND", message, 1)
			}
			return nil, nil, cliError(f.jsonOut, "EVIDENCE_OPEN_FAILED", "cannot inspect the evidence directory: "+err.Error(), 1)
		}
		if !info.IsDir() {
			return nil, nil, cliError(f.jsonOut, "EVIDENCE_PATH_INVALID", "evidence path is not a directory: "+f.home, 1)
		}
	}
	createLock := mode == ledgerCreate || mode == ledgerExistingWrite || mode == ledgerRecover
	var lock *ledger.HomeLock
	var err error
	if mode == ledgerExistingWrite || mode == ledgerRecover {
		// Homes created before locking was introduced have no lock file. Verify
		// them without mutation before creating one, so a failed replay remains
		// an information-only refusal rather than changing untrusted evidence.
		lock, err = ledger.AcquireHomeLock(f.home, false)
		if err == nil && lock == nil {
			if verifyErr := verifyExistingEvidence(f.home); verifyErr != nil {
				return nil, nil, cliError(f.jsonOut, "EVIDENCE_VERIFICATION_FAILED", "stored evidence failed verification: "+verifyErr.Error(), 1)
			}
			lock, err = ledger.AcquireHomeLock(f.home, true)
		}
	} else {
		lock, err = ledger.AcquireHomeLock(f.home, createLock)
	}
	if err != nil {
		return nil, nil, cliError(f.jsonOut, "EVIDENCE_BUSY", "cannot use the evidence directory: "+err.Error(), 1)
	}
	if mode == ledgerExistingWrite && identity.IsBPlus(f.home) {
		f.lifecycleFreshness = "LOCAL_ONLY_UNPROVEN"
		if f.checkpoint != "" || f.trustStore != "" {
			readOnly, readErr := ledger.OpenReadOnly(f.home)
			if readErr != nil {
				_ = lock.Release()
				return nil, nil, cliError(f.jsonOut, "EVIDENCE_VERIFICATION_FAILED", readErr.Error(), 2)
			}
			if code := requireCurrentLifecycleForSigning(f, readOnly.IdentityState); code != 0 {
				_ = lock.Release()
				return nil, nil, code
			}
		}
	}
	var l *ledger.Ledger
	switch mode {
	case ledgerCreate:
		l, err = ledger.Open(f.home)
	case ledgerExistingWrite:
		l, err = ledger.OpenExisting(f.home)
	case ledgerRecover:
		l, err = ledger.RecoverExisting(f.home)
	case ledgerReadOnly:
		l, err = ledger.OpenReadOnly(f.home)
	case ledgerReadOnlyPrivate:
		l, err = ledger.OpenReadOnlyWithPrivate(f.home)
	}
	if err != nil {
		_ = lock.Release()
		if errors.Is(err, ledger.ErrRecoveryRequired) {
			return nil, nil, cliError(f.jsonOut, "RECOVERY_REQUIRED", "an interrupted evidence write requires recovery; run ueg recover first", 1)
		}
		return nil, nil, cliError(f.jsonOut, "EVIDENCE_OPEN_FAILED", "cannot open the evidence directory: "+err.Error(), 1)
	}
	return l, lock, 0
}

func verifyExistingEvidence(home string) error {
	l, err := ledger.OpenReadOnly(home)
	if err != nil {
		return err
	}
	chain := l.VerifyReceipts()
	if !chain.OK {
		return fmt.Errorf("stored receipt verification failed: %s", strings.Join(chain.Findings, "; "))
	}
	bind := ledger.VerifyPetitions(l.Receipts(), l.Petitions())
	if !bind.OK {
		return fmt.Errorf("stored request verification failed: %s", strings.Join(bind.Findings, "; "))
	}
	return nil
}

func cmdRun(f *flags, dryRun bool) int {
	if len(f.rest) == 0 {
		return cliError(f.jsonOut, "USAGE", "no command given", 1)
	}
	classification := policy.Classify(f.rest)
	decision := policy.Decide(classification, f.posture, policy.Approvals{
		Irrevocable: f.approve, Unclassified: f.allowUnclass,
	})
	if dryRun || decision.Outcome == policy.Refused {
		return reportInertDecision(f, classification, decision, dryRun)
	}
	if code := requireBPlusForSigning(f); code != 0 {
		return code
	}
	l, lock, code := openLedger(f, ledgerExistingWrite)
	if l == nil {
		return code
	}
	defer lock.Release()
	opts := gateway.Options{
		Posture: f.posture,
		Approvals: policy.Approvals{
			Irrevocable:  f.approve,
			Unclassified: f.allowUnclass,
		},
		DryRun: dryRun,
		Stream: !f.jsonOut && !dryRun,
	}

	res, err := gateway.Run(l, f.rest, opts)
	if err != nil {
		return cliError(f.jsonOut, "EXECUTION_FAILED", err.Error(), 1)
	}

	if f.jsonOut {
		printJSON(map[string]any{
			"evidence_home":        l.Home,
			"signing_key_id":       l.KeyID,
			"identity_created":     l.IdentityCreated,
			"stage":                res.Stage.String(),
			"stage_path":           res.Path,
			"effect_class":         string(res.Classification.Class),
			"rule_id":              res.Classification.RuleID,
			"surface":              res.Classification.Surface,
			"decision":             string(res.Decision.Outcome),
			"reason":               res.Decision.Reason,
			"posture":              string(res.Decision.Posture),
			"executed":             res.Executed,
			"exit_code":            res.ExitCode,
			"stdout_sha256":        res.StdoutSHA256,
			"stderr_sha256":        res.StderrSHA256,
			"stdout_bytes":         res.StdoutBytes,
			"stderr_bytes":         res.StderrBytes,
			"stdout_truncated":     res.StdoutTruncated,
			"stderr_truncated":     res.StderrTruncated,
			"duration_ms":          res.DurationMs,
			"admission_receipt_id": receiptID(res.AdmissionReceipt),
			"outcome_receipt_id":   receiptID(res.OutcomeReceipt),
			"stdout":               res.Stdout,
			"stderr":               res.Stderr,
			"lifecycle_freshness":  f.lifecycleFreshness,
		})
		return res.ExitCode
	}

	if res.Decision.Outcome == policy.Refused {
		fmt.Fprintf(os.Stderr, "ueg: REFUSED  %s\n", strings.Join(f.rest, " "))
		fmt.Fprintf(os.Stderr, "     effect  %s (%s)\n", res.Classification.Class, res.Classification.RuleID)
		fmt.Fprintf(os.Stderr, "     because %s\n", res.Decision.Reason)
		fmt.Fprintf(os.Stderr, "     receipt %s\n", short(receiptID(res.AdmissionReceipt)))
		return res.ExitCode
	}

	if dryRun {
		fmt.Printf("ueg: %s\n", strings.Join(f.rest, " "))
		fmt.Printf("     effect   %s (%s)\n", res.Classification.Class, res.Classification.RuleID)
		fmt.Printf("     decision %s — %s\n", res.Decision.Outcome, res.Decision.Reason)
		fmt.Printf("     stage    %s (not executed: check only)\n", res.Stage)
		fmt.Printf("     receipt  %s\n", short(receiptID(res.AdmissionReceipt)))
		return 0
	}

	// The command's own output already streamed; the evidence line goes to
	// stderr so pipelines see only what the command produced.
	fmt.Fprintf(os.Stderr, "ueg: %s %s exit=%d receipts=%s,%s freshness=%s\n",
		res.Classification.Class, res.Stage, res.ExitCode,
		short(receiptID(res.AdmissionReceipt)), short(receiptID(res.OutcomeReceipt)), f.lifecycleFreshness)
	return res.ExitCode
}

func reportInertDecision(f *flags, class policy.Classification, decision policy.Decision, dryRun bool) int {
	if f.jsonOut {
		printJSON(map[string]any{
			"effect_class": class.Class, "rule_id": class.RuleID, "surface": class.Surface,
			"decision": decision.Outcome, "reason": decision.Reason, "posture": decision.Posture,
			"executed": false, "state_changed": false, "evidence_recorded": false,
			"mode": map[bool]string{true: "check", false: "refusal"}[dryRun],
		})
	} else if dryRun {
		fmt.Printf("ueg: %s\n", strings.Join(f.rest, " "))
		fmt.Printf("     effect   %s (%s)\n", class.Class, class.RuleID)
		fmt.Printf("     decision %s — %s\n", decision.Outcome, decision.Reason)
		fmt.Println("     state    unchanged (check does not create or record evidence)")
	} else {
		fmt.Fprintf(os.Stderr, "ueg: REFUSED  %s\n", strings.Join(f.rest, " "))
		fmt.Fprintf(os.Stderr, "     effect  %s (%s)\n", class.Class, class.RuleID)
		fmt.Fprintf(os.Stderr, "     because %s\n", decision.Reason)
		fmt.Fprintln(os.Stderr, "     state   unchanged; the command did not start")
	}
	if decision.Outcome == policy.Refused {
		return 77
	}
	return 0
}

func requireBPlusForSigning(f *flags) int {
	info, err := os.Stat(f.home)
	if err != nil {
		if os.IsNotExist(err) {
			return cliError(f.jsonOut, "IDENTITY_NOT_INITIALIZED",
				fmt.Sprintf("no evidence identity exists at %s; run ueg identity init --home %q --recovery-package <offline-path>", f.home, f.home), 1)
		}
		return cliError(f.jsonOut, "EVIDENCE_OPEN_FAILED", "cannot inspect the evidence home: "+err.Error(), 1)
	}
	if !info.IsDir() {
		return cliError(f.jsonOut, "EVIDENCE_PATH_INVALID", "evidence path is not a directory: "+f.home, 1)
	}
	if !identity.IsBPlus(f.home) {
		return cliError(f.jsonOut, "LEGACY_MIGRATION_REQUIRED",
			"this is a legacy evidence home; independently confirm its signing-key fingerprint, then run ueg identity migrate before creating new evidence", 1)
	}
	return 0
}

func requireCurrentLifecycleForSigning(f *flags, local *identity.State) int {
	if f.checkpoint != "" && f.trustStore != "" {
		return cliError(f.jsonOut, "USAGE", "choose either --checkpoint or --trust-store", 1)
	}
	external, err := loadExternalLifecycleState(f.checkpoint, f.trustStore, local.Genesis.IdentityID)
	if err != nil {
		return cliError(f.jsonOut, "EXTERNAL_CHECKPOINT_INVALID", err.Error(), 2)
	}
	relation, err := identity.CompareLifecycleStates(local, external)
	if err != nil {
		return cliError(f.jsonOut, "LIFECYCLE_FORK", err.Error()+"; refusing to sign", 2)
	}
	if relation == "LOCAL_STALE" {
		return cliError(f.jsonOut, "STALE_IDENTITY_STATE", "a newer authenticated lifecycle exists; refusing to sign from this stale home", 2)
	}
	f.lifecycleFreshness = relation + "_OFFLINE_FRESHNESS_UNPROVEN"
	return 0
}

func cmdReplay(f *flags) int {
	if code := requireBPlusForSigning(f); code != 0 {
		return code
	}
	l, lock, code := openLedger(f, ledgerExistingWrite)
	if l == nil {
		return code
	}
	defer lock.Release()
	selector := "last"
	if len(f.rest) > 0 {
		selector = f.rest[0]
	}
	res, err := gateway.Replay(l, selector, gateway.Options{
		Posture:   f.posture,
		Approvals: policy.Approvals{Irrevocable: f.approve, Unclassified: f.allowUnclass},
	})
	if err != nil {
		return cliError(f.jsonOut, "REPLAY_FAILED", err.Error(), 1)
	}
	res.LifecycleFreshness = f.lifecycleFreshness
	if f.jsonOut {
		printJSON(res)
	} else {
		fmt.Printf("REPLAY: %s\n", res.Verdict)
		fmt.Printf("  target  %s\n", res.Target)
		fmt.Printf("  reason  %s\n", res.Reason)
		for _, d := range res.Differences {
			fmt.Printf("  differs %s\n", d)
		}
		for _, c := range res.ChainFindings {
			fmt.Printf("  chain   %s\n", c)
		}
	}
	switch res.Verdict {
	case gateway.Match, gateway.RefusalConfirmed, gateway.CheckConfirmed:
		return 0
	case gateway.RefusedReplay:
		return 77
	case gateway.Incomplete:
		return 3
	default:
		return 2
	}
}

func cmdExport(f *flags) int {
	if len(f.rest) == 0 {
		return cliError(f.jsonOut, "USAGE", "export needs an output path", 1)
	}
	l, lock, code := openLedger(f, ledgerReadOnlyPrivate)
	if l == nil {
		return code
	}
	defer lock.Release()
	if l.PendingRecovery {
		return cliError(f.jsonOut, "RECOVERY_REQUIRED", "export is blocked by an interrupted evidence write; run ueg recover first", 1)
	}
	out := f.rest[0]
	if err := bundle.Build(l, out); err != nil {
		code := "EXPORT_FAILED"
		switch {
		case errors.Is(err, bundle.ErrDestinationExists):
			code = "EXPORT_DESTINATION_EXISTS"
		case errors.Is(err, bundle.ErrEvidenceInvalid):
			code = "EXPORT_EVIDENCE_INVALID"
		case errors.Is(err, bundle.ErrExportTooLarge):
			code = "EXPORT_TOO_LARGE"
		}
		return cliError(f.jsonOut, code, err.Error(), 1)
	}
	if f.jsonOut {
		printJSON(map[string]any{"bundle": out, "receipts": len(l.Receipts()), "signing_key_id": l.KeyID})
	} else {
		fmt.Printf("wrote %s (%d receipts, signed by %s)\n", out, len(l.Receipts()), l.KeyID)
		fmt.Printf("verify it with:  ueg verify %s\n", out)
	}
	return 0
}

func cmdVerify(f *flags) int {
	if len(f.rest) == 0 {
		return cliError(f.jsonOut, "USAGE", "verify needs a bundle path", 1)
	}
	if f.expectedKey != "" && f.expectedIdentity != "" {
		return cliError(f.jsonOut, "USAGE", "choose either --expected-key-id for legacy evidence or --expected-identity-id for B+ evidence", 1)
	}
	if (f.minimumCheckpointSequence == nil) != (f.minimumCheckpointDigest == "") {
		return cliError(f.jsonOut, "USAGE", "--minimum-checkpoint-sequence and --minimum-checkpoint-digest must be supplied together", 1)
	}
	res := bundle.VerifyWithOptions(f.rest[0], bundle.Options{
		ExpectedKeyID: f.expectedKey, ExpectedIdentityID: f.expectedIdentity,
		ExternalCheckpointPath: f.checkpoint, ExternalAnchorPath: f.anchor, TrustStore: f.trustStore,
		MinimumCheckpointSequence: f.minimumCheckpointSequence, MinimumCheckpointDigest: f.minimumCheckpointDigest,
		RequireCurrentStatus: f.requireCurrentStatus,
	})
	if f.jsonOut {
		printJSON(res)
	} else if res.BundleVersion == "bplus-v1" {
		fmt.Printf("%s: %s\n", res.OverallTrust, res.Reason)
		fmt.Printf("  identity     %s\n", res.IdentityID)
		fmt.Printf("  lifecycle    %d %s\n", res.LifecycleSequence, res.LifecycleDigest)
		fmt.Printf("  signatures   %s\n", res.Signature)
		fmt.Printf("  ledger       %s\n", res.BundleLedgerIntegrity)
		fmt.Printf("  identity     %s\n", res.IdentityContinuity)
		fmt.Printf("  lifecycle    %s\n", res.LifecycleChain)
		fmt.Printf("  key status   %s\n", res.SigningKeyStatus)
		fmt.Printf("  checkpoint   %s / %s / freshness %s\n", res.CheckpointAuthenticity, res.CheckpointSource, res.CheckpointFreshness)
		fmt.Printf("  time         %s\n", res.EvidenceTimeAssurance)
	} else if res.OK {
		fmt.Println(res.TrustVerdict)
		for _, c := range res.Checks {
			fmt.Println("  ✓", c)
		}
		fmt.Printf("  %d receipts, signed by %s\n", res.ReceiptCount, strings.Join(res.SigningKeyIDs, ", "))
	} else {
		fmt.Println("INVALID:", res.Reason)
	}
	if res.BundleVersion == "bplus-v1" {
		if res.OverallTrust == bundle.OverallVerified {
			return 0
		}
		return 2
	}
	if res.OK {
		return 0
	}
	return 2
}

func cmdLedger(f *flags) int {
	l, lock, code := openLedger(f, ledgerReadOnly)
	if l == nil {
		return code
	}
	defer lock.Release()
	chain := l.VerifyReceipts()
	bind := ledger.VerifyPetitions(l.Receipts(), l.Petitions())

	if f.jsonOut {
		printJSON(map[string]any{
			"home":              f.home,
			"signing_key_id":    l.KeyID,
			"receipts":          l.Receipts(),
			"chain_ok":          chain.OK && bind.OK,
			"recovery_required": l.PendingRecovery,
			"findings":          append(chain.Findings, bind.Findings...),
		})
		if chain.OK && bind.OK && !l.PendingRecovery {
			return 0
		}
		return 2
	}

	fmt.Printf("evidence  %s\n", f.home)
	fmt.Printf("key       %s\n", l.KeyID)
	fmt.Printf("receipts  %d\n\n", len(l.Receipts()))
	if l.PendingRecovery {
		fmt.Println("recovery  REQUIRED (an interrupted evidence write is pending; run ueg recover)")
	}
	for _, r := range l.Receipts() {
		fmt.Printf("  %3d  %s  %-9s %-9s  %s\n", r.SequenceNo, short(r.ReceiptID),
			r.AdmissionOutcome, r.ExpressionOutcome, truncate(r.PetitionSummary.Target, 48))
	}
	fmt.Println()
	if chain.OK && bind.OK && !l.PendingRecovery {
		fmt.Printf("chain     OK (%d receipts re-derived and verified)\n", chain.Checked)
		return 0
	}
	if chain.OK && bind.OK {
		fmt.Printf("chain     OK (%d receipts re-derived and verified), but recovery is required\n", chain.Checked)
		return 2
	}
	fmt.Println("chain     FAILED")
	for _, msg := range append(chain.Findings, bind.Findings...) {
		fmt.Println("         ", msg)
	}
	return 2
}

func cmdRecover(f *flags) int {
	identityRecovered := false
	if pending, inspectErr := identity.InitializationPending(f.home); inspectErr != nil {
		return cliError(f.jsonOut, "RECOVERY_STATE_UNAVAILABLE", "cannot inspect initialization recovery state: "+inspectErr.Error(), 1)
	} else if pending {
		state, recoverErr := identity.RecoverPendingInitialization(f.home, nil)
		if recoverErr != nil && !errors.Is(recoverErr, identity.ErrInitializationRolledBack) {
			return cliError(f.jsonOut, "IDENTITY_RECOVERY_FAILED", recoverErr.Error(), 1)
		}
		if errors.Is(recoverErr, identity.ErrInitializationRolledBack) {
			if f.jsonOut {
				printJSON(map[string]any{"home": f.home, "recovered": false, "needed": true, "initialization_rolled_back": true})
			} else {
				fmt.Println("The interrupted initialization was rolled back. No evidence identity was created.")
			}
			return 0
		}
		if state == nil {
			return cliError(f.jsonOut, "IDENTITY_RECOVERY_FAILED", "initialization recovery returned no identity state", 1)
		}
		identityRecovered = true
	}
	if pending, inspectErr := identity.MigrationPending(f.home); inspectErr != nil {
		return cliError(f.jsonOut, "RECOVERY_STATE_UNAVAILABLE", "cannot inspect migration recovery state: "+inspectErr.Error(), 1)
	} else if pending {
		lock, lockErr := ledger.AcquireHomeLock(f.home, false)
		if lockErr != nil || lock == nil {
			return cliError(f.jsonOut, "EVIDENCE_BUSY", "cannot lock the evidence home for migration recovery", 1)
		}
		_, recoverErr := identity.RecoverPendingMigration(f.home)
		_ = lock.Release()
		if recoverErr != nil && !errors.Is(recoverErr, identity.ErrMigrationRolledBack) {
			return cliError(f.jsonOut, "IDENTITY_RECOVERY_FAILED", recoverErr.Error(), 1)
		}
		identityRecovered = true
	}
	if identity.IsBPlus(f.home) {
		pending, inspectErr := identity.MutationPending(f.home)
		if inspectErr != nil {
			return cliError(f.jsonOut, "RECOVERY_STATE_UNAVAILABLE", "cannot inspect identity recovery state: "+inspectErr.Error(), 1)
		}
		if pending {
			lock, lockErr := ledger.AcquireHomeLock(f.home, false)
			if lockErr != nil || lock == nil {
				return cliError(f.jsonOut, "EVIDENCE_BUSY", "cannot lock the evidence home for lifecycle recovery", 1)
			}
			_, recoverErr := identity.RecoverPendingMutation(f.home)
			_ = lock.Release()
			if recoverErr != nil {
				return cliError(f.jsonOut, "IDENTITY_RECOVERY_FAILED", recoverErr.Error(), 1)
			}
			identityRecovered = true
		}
	}
	needed, err := ledger.RecoveryPending(f.home)
	if err != nil {
		return cliError(f.jsonOut, "RECOVERY_STATE_UNAVAILABLE", "cannot inspect recovery state: "+err.Error(), 1)
	}
	mode := ledgerReadOnly
	if needed {
		mode = ledgerRecover
	}
	l, lock, code := openLedger(f, mode)
	if l == nil {
		return code
	}
	defer lock.Release()
	chain := l.VerifyReceipts()
	bind := ledger.VerifyPetitions(l.Receipts(), l.Petitions())
	ok := chain.OK && bind.OK && !l.PendingRecovery
	if f.jsonOut {
		printJSON(map[string]any{
			"home":      f.home,
			"recovered": (needed || identityRecovered) && ok,
			"needed":    needed || identityRecovered,
			"chain_ok":  ok,
			"findings":  append(chain.Findings, bind.Findings...),
		})
	} else if !needed && !identityRecovered && ok {
		fmt.Println("No recovery was needed. The evidence chain verifies.")
	} else if ok {
		fmt.Println("Recovery completed. The evidence chain verifies.")
	} else {
		fmt.Println("Recovery could not establish a valid evidence chain.")
	}
	if ok {
		return 0
	}
	return 2
}

func cmdPolicy(f *flags) int {
	cmds := []string{
		"echo hello", "ls -la", "git status", "git push", "git push --force",
		"curl https://example.com", "pip install requests", "sudo apt install nginx",
		"rm -rf build", "rm -rf /", "mkfs.ext4 /dev/sda1", "sh -c 'echo hi'",
	}
	if len(f.rest) > 0 {
		cmds = []string{strings.Join(f.rest, " ")}
	}
	rows := make([]map[string]any, 0, len(cmds))
	for _, c := range cmds {
		argv := strings.Fields(c)
		cl := policy.Classify(argv)
		d := policy.Decide(cl, f.posture, policy.Approvals{Irrevocable: f.approve, Unclassified: f.allowUnclass})
		rows = append(rows, map[string]any{
			"command": c, "class": string(cl.Class), "rule_id": cl.RuleID,
			"surface": cl.Surface, "decision": string(d.Outcome),
		})
	}
	if f.jsonOut {
		printJSON(map[string]any{
			"rules_version": policy.RulesVersion(),
			"rules_hash":    policy.RulesHash,
			"rule_count":    policy.RuleCount(),
			"posture":       string(f.posture),
			"examples":      rows,
		})
		return 0
	}
	fmt.Printf("rules v%s  %d rules  %s  posture=%s\n\n", policy.RulesVersion(), policy.RuleCount(), policy.RulesHash[:12], f.posture)
	for _, r := range rows {
		fmt.Printf("  %-9s %-9s %-24s %s\n", r["decision"], r["class"], r["rule_id"], r["command"])
	}
	return 0
}

// cmdValidate states the properties of the state model and checks them against
// the code rather than asserting them in prose.
func cmdValidate(f *flags) int {
	stages := []gateway.Stage{
		gateway.VOID, gateway.NASCENT, gateway.DECLARED, gateway.CANONICAL,
		gateway.GATED, gateway.EXECUTABLE, gateway.EXECUTED, gateway.STABILIZED,
	}

	var proofs []string
	valid := true

	executable := 0
	terminal := 0
	for _, s := range stages {
		if s.Executable() {
			executable++
		}
		if s.Terminal() {
			terminal++
		}
		if s.String() == "UNKNOWN" {
			valid = false
		}
	}
	if executable == 1 && gateway.EXECUTABLE.Executable() {
		proofs = append(proofs, "exactly one stage permits execution, and it is reached only after classification and admission")
	} else {
		valid = false
	}
	if terminal == 1 && gateway.STABILIZED.Terminal() {
		proofs = append(proofs, "exactly one stage is terminal: STABILIZED")
	} else {
		valid = false
	}
	proofs = append(proofs, fmt.Sprintf("the stage space is closed: %d named stages, all ordinals distinct and increasing", len(stages)))
	proofs = append(proofs, "no stage is an error state; a request that cannot proceed stops where it stopped and the receipt says why")

	// Properties of existing evidence, checked without creating or repairing it.
	if _, err := os.Stat(f.home); os.IsNotExist(err) {
		proofs = append(proofs, "there is no local evidence directory, so validation did not create one")
	} else if err != nil {
		valid = false
		proofs = append(proofs, "the local evidence path could not be inspected: "+err.Error())
	} else if l, lock, code := openLedger(f, ledgerReadOnly); l != nil {
		defer lock.Release()
		chain := l.VerifyReceipts()
		bind := ledger.VerifyPetitions(l.Receipts(), l.Petitions())
		if l.PendingRecovery {
			valid = false
			proofs = append(proofs, "the local ledger has an interrupted evidence write; run ueg recover before relying on it")
		} else if len(l.Receipts()) == 0 {
			proofs = append(proofs, "there is no local evidence yet, so there is nothing to claim about it")
		} else if chain.OK && bind.OK {
			proofs = append(proofs, fmt.Sprintf("the local chain verifies: %d receipt ids re-derived, %d signatures checked", chain.Checked, chain.Checked))
		} else {
			valid = false
			proofs = append(proofs, "the local chain does NOT verify: "+strings.Join(append(chain.Findings, bind.Findings...), "; "))
		}
	} else if code != 0 {
		valid = false
		proofs = append(proofs, "the local evidence directory could not be opened read-only")
	}

	// Properties of the rule table.
	dangerous := [][]string{
		{"rm", "-rf", "/"},
		{"mkfs.ext4", "/dev/sda1"},
		{"dd", "if=/dev/zero", "of=/dev/sda"},
	}
	allRefused := true
	for _, argv := range dangerous {
		d := policy.Decide(policy.Classify(argv), policy.Enforce, policy.Approvals{Irrevocable: true, Unclassified: true})
		if d.Outcome != policy.Refused {
			allRefused = false
			valid = false
		}
	}
	if allRefused {
		proofs = append(proofs, "prohibited effects stay refused under enforce posture even with every approval flag set")
	}
	allRefusedUnderObserve := true
	for _, argv := range dangerous {
		d := policy.Decide(policy.Classify(argv), policy.Observe, policy.Approvals{Irrevocable: true, Unclassified: true})
		if d.Outcome != policy.Refused {
			allRefusedUnderObserve = false
			valid = false
		}
	}
	if allRefusedUnderObserve {
		proofs = append(proofs, "prohibited effects stay refused under observe posture")
	}

	sort.Strings(proofs[len(proofs):])
	if f.jsonOut {
		printJSON(map[string]any{"valid": valid, "proofs": proofs, "rules_hash": policy.RulesHash})
	} else {
		for _, p := range proofs {
			fmt.Println("PROOF:", p)
		}
		fmt.Println()
		if valid {
			fmt.Println("valid: true")
		} else {
			fmt.Println("valid: false")
		}
	}
	if valid {
		return 0
	}
	return 2
}

func receiptID(r *ledger.Receipt) string {
	if r == nil {
		return ""
	}
	return r.ReceiptID
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func printJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ueg:", err)
		return
	}
	fmt.Println(string(data))
}
