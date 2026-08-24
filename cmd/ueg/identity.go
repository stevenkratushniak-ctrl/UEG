package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/stevenkratushniak-ctrl/ueg/internal/identity"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
)

const identityUsage = `Usage: ueg identity <command> [flags]

Create and manage one B+ Evidence Identity for one evidence home:
  init                 Create a new identity and encrypted offline recovery package
  migrate              Enroll a verified legacy signing key as epoch zero (one way)
  status               Verify and show identity and operational-key status
  recovery-verify      Decrypt and self-test an offline recovery package
  rotate               Rotate to a new operational key and retire the old epoch
  transfer             Official device-transfer transition (a rotation)
  suspend              Stop signing until root-authorized resumption
  resume               Resume a suspended operational epoch
  recover              Replace a lost operational key; does not restore lost evidence
  revoke               Permanently revoke the current operational epoch
  card                 Export a public identity card
  anchor               Export a signed anchor for the exact current ledger head
  checkpoint export    Export the complete authenticated lifecycle checkpoint
  checkpoint import    Retain monotonic lifecycle status in an explicit trust store
  transaction-recover  Complete or safely roll back an interrupted lifecycle mutation

Passphrases are read from a hidden terminal prompt. For local automation, use
--passphrase-stdin and send the passphrase on standard input. A passphrase is
never accepted as a command-line value.

An Evidence Identity proves pseudonymous cryptographic continuity for one UEG
ledger. It does not identify a person, organization, device, legal authority,
trusted time, evidence truth, admissibility, or nonrepudiation.
`

var identityCommandUsage = map[string]string{
	"init": `Usage: ueg identity init --home <new-dir> --recovery-package <new-file> [--label <advisory-name>] [--passphrase-stdin] [--json]
`,
	"migrate": `Usage: ueg identity migrate --home <legacy-dir> --recovery-package <new-file> --confirm-key-id <fingerprint> --confirm-not-compromised [--label <advisory-name>] [--passphrase-stdin] [--json]
`,
	"status": `Usage: ueg identity status [--home <dir>] [--checkpoint <file> | --trust-store <dir>] [--json]
`,
	"recovery-verify": `Usage: ueg identity recovery-verify --recovery-package <file> --identity-id <genesis-pin> [--passphrase-stdin] [--json]
`,
	"rotate": `Usage: ueg identity rotate [--home <dir>] --recovery-package <file> --reason <code> [--anchor <known-good-file>] [--checkpoint <file> | --trust-store <dir>] [--passphrase-stdin] [--json]
`,
	"transfer": `Usage: ueg identity transfer [--home <dir>] --recovery-package <file> --reason <code> [--anchor <known-good-file>] [--checkpoint <file> | --trust-store <dir>] [--passphrase-stdin] [--json]
`,
	"suspend": `Usage: ueg identity suspend [--home <dir>] --recovery-package <file> --reason <code> [--anchor <known-good-file>] [--checkpoint <file> | --trust-store <dir>] [--passphrase-stdin] [--json]
`,
	"resume": `Usage: ueg identity resume [--home <dir>] --recovery-package <file> --reason <code> [--checkpoint <file> | --trust-store <dir>] [--passphrase-stdin] [--json]
`,
	"recover": `Usage: ueg identity recover [--home <dir>] --recovery-package <file> --reason <code> [--anchor <known-good-file>] [--checkpoint <file> | --trust-store <dir>] [--passphrase-stdin] [--json]
`,
	"revoke": `Usage: ueg identity revoke [--home <dir>] --recovery-package <file> --reason <code> --confirm-key-id <fingerprint> --confirm-compromise [--anchor <known-good-file>] [--checkpoint <file> | --trust-store <dir>] [--passphrase-stdin] [--json]
`,
	"card": `Usage: ueg identity card [--home <dir>] --output <new-file> [--json]
`,
	"anchor": `Usage: ueg identity anchor [--home <dir>] --output <new-file> [--json]
`,
	"checkpoint-export": `Usage: ueg identity checkpoint export [--home <dir>] --output <new-file> [--json]
`,
	"checkpoint-import": `Usage: ueg identity checkpoint import --input <file> --trust-store <dir> --identity-id <genesis-pin> [--json]
`,
	"transaction-recover": `Usage: ueg identity transaction-recover [--home <dir>] [--json]
`,
}

type identityOptions struct {
	home                  string
	recoveryPackage       string
	label                 string
	output                string
	input                 string
	trustStore            string
	checkpoint            string
	identityID            string
	reason                string
	anchor                string
	confirmKeyID          string
	jsonOut               bool
	passphraseStdin       bool
	confirmNotCompromised bool
	confirmCompromise     bool
	help                  bool
	seen                  map[string]bool
}

var identityAllowed = map[string]map[string]bool{
	"init":                flagsAllowed("home", "recovery-package", "label", "passphrase-stdin", "json"),
	"migrate":             flagsAllowed("home", "recovery-package", "label", "confirm-key-id", "confirm-not-compromised", "passphrase-stdin", "json"),
	"status":              flagsAllowed("home", "checkpoint", "trust-store", "json"),
	"recovery-verify":     flagsAllowed("recovery-package", "identity-id", "passphrase-stdin", "json"),
	"rotate":              flagsAllowed("home", "recovery-package", "reason", "anchor", "checkpoint", "trust-store", "passphrase-stdin", "json"),
	"transfer":            flagsAllowed("home", "recovery-package", "reason", "anchor", "checkpoint", "trust-store", "passphrase-stdin", "json"),
	"suspend":             flagsAllowed("home", "recovery-package", "reason", "anchor", "checkpoint", "trust-store", "passphrase-stdin", "json"),
	"resume":              flagsAllowed("home", "recovery-package", "reason", "checkpoint", "trust-store", "passphrase-stdin", "json"),
	"recover":             flagsAllowed("home", "recovery-package", "reason", "anchor", "checkpoint", "trust-store", "passphrase-stdin", "json"),
	"revoke":              flagsAllowed("home", "recovery-package", "reason", "anchor", "checkpoint", "trust-store", "confirm-key-id", "confirm-compromise", "passphrase-stdin", "json"),
	"card":                flagsAllowed("home", "output", "json"),
	"anchor":              flagsAllowed("home", "output", "json"),
	"checkpoint-export":   flagsAllowed("home", "output", "json"),
	"checkpoint-import":   flagsAllowed("input", "trust-store", "identity-id", "json"),
	"transaction-recover": flagsAllowed("home", "json"),
}

func flagsAllowed(names ...string) map[string]bool {
	out := map[string]bool{"help": true}
	for _, name := range names {
		out[name] = true
	}
	return out
}

func cmdIdentity(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		if len(args) == 2 {
			if text, ok := identityCommandUsage[args[1]]; ok {
				fmt.Print(text)
				return 0
			}
		}
		fmt.Print(identityUsage)
		return 0
	}
	action := args[0]
	rest := args[1:]
	if action == "checkpoint" {
		if len(rest) == 0 || rest[0] == "-h" || rest[0] == "--help" {
			fmt.Print(identityCommandUsage["checkpoint-export"])
			fmt.Print(identityCommandUsage["checkpoint-import"])
			return 0
		}
		action += "-" + rest[0]
		rest = rest[1:]
	}
	if _, ok := identityAllowed[action]; !ok {
		return cliError(jsonRequested(rest), "USAGE", fmt.Sprintf("unknown identity command %q; run ueg identity --help", action), 1)
	}
	opts, err := parseIdentityOptions(action, rest)
	if err != nil {
		return cliError(jsonRequested(rest), "USAGE", err.Error(), 1)
	}
	if opts.help {
		fmt.Print(identityCommandUsage[action])
		return 0
	}

	switch action {
	case "init":
		return identityInit(opts)
	case "migrate":
		return identityMigrate(opts)
	case "status":
		return identityStatus(opts)
	case "recovery-verify":
		return identityRecoveryVerify(opts)
	case "rotate", "transfer", "suspend", "resume", "recover", "revoke":
		return identityMutate(action, opts)
	case "card", "anchor", "checkpoint-export":
		return identityExportArtifact(action, opts)
	case "checkpoint-import":
		return identityImportCheckpoint(opts)
	case "transaction-recover":
		return identityRecoverTransaction(opts)
	}
	return 1
}

func parseIdentityOptions(action string, args []string) (*identityOptions, error) {
	opts := &identityOptions{home: defaultHome(), seen: map[string]bool{}}
	allowed := identityAllowed[action]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			opts.help = true
			opts.seen["help"] = true
			continue
		}
		if !strings.HasPrefix(arg, "--") {
			return nil, fmt.Errorf("identity %s does not accept positional argument %q", action, arg)
		}
		name := strings.TrimPrefix(arg, "--")
		value := ""
		hasValue := false
		if at := strings.IndexByte(name, '='); at >= 0 {
			value, name, hasValue = name[at+1:], name[:at], true
		}
		if !allowed[name] {
			return nil, fmt.Errorf("--%s is not valid for identity %s", name, strings.ReplaceAll(action, "-", " "))
		}
		if opts.seen[name] {
			return nil, fmt.Errorf("--%s may be supplied only once", name)
		}
		opts.seen[name] = true
		switch name {
		case "json":
			opts.jsonOut = true
		case "passphrase-stdin":
			opts.passphraseStdin = true
		case "confirm-not-compromised":
			opts.confirmNotCompromised = true
		case "confirm-compromise":
			opts.confirmCompromise = true
		default:
			if !hasValue {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("--%s needs a value", name)
				}
				i++
				value = args[i]
			}
			if strings.TrimSpace(value) == "" {
				return nil, fmt.Errorf("--%s needs a non-empty value", name)
			}
			switch name {
			case "home":
				opts.home = value
			case "recovery-package":
				opts.recoveryPackage = value
			case "label":
				opts.label = value
			case "output":
				opts.output = value
			case "input":
				opts.input = value
			case "trust-store":
				opts.trustStore = value
			case "checkpoint":
				opts.checkpoint = value
			case "identity-id":
				opts.identityID = value
			case "reason":
				opts.reason = value
			case "anchor":
				opts.anchor = value
			case "confirm-key-id":
				opts.confirmKeyID = value
			}
		}
	}
	return opts, nil
}

func defaultHome() string {
	if value := os.Getenv("UEG_HOME"); value != "" {
		return value
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ueg"
	}
	return filepath.Join(home, ".ueg")
}

func identityInit(opts *identityOptions) int {
	if !opts.seen["home"] || opts.recoveryPackage == "" {
		return identityUsageError(opts, "init requires an explicit --home and --recovery-package", "init")
	}
	passphrase, err := readPassphrase(opts)
	if err != nil {
		return cliError(opts.jsonOut, "PASSPHRASE_UNAVAILABLE", err.Error(), 1)
	}
	defer wipe(passphrase)
	state, err := identity.Initialize(opts.home, opts.recoveryPackage, passphrase, opts.label)
	if err != nil {
		return cliError(opts.jsonOut, "IDENTITY_INITIALIZATION_FAILED", err.Error(), 1)
	}
	printIdentityMutationResult(opts, "INITIALIZED", state, state.Records[0], map[string]any{
		"recovery_package": opts.recoveryPackage,
	})
	return 0
}

func identityStatus(opts *identityOptions) int {
	state, err := identity.LoadPublic(opts.home)
	if err != nil {
		return cliError(opts.jsonOut, "IDENTITY_STATUS_FAILED", err.Error(), 1)
	}
	activeEpoch := any(nil)
	activeKey := ""
	status := state.Epochs[len(state.Epochs)-1].Status
	if active := state.Active(); active != nil {
		activeEpoch = active.EpochNumber
		activeKey = active.OperationalKeyID
		status = active.Status
	}
	freshness := "LOCAL_ONLY_UNPROVEN"
	if opts.checkpoint != "" && opts.trustStore != "" {
		return identityUsageError(opts, "status accepts either --checkpoint or --trust-store, not both", "status")
	}
	if opts.checkpoint != "" || opts.trustStore != "" {
		external, externalErr := loadExternalLifecycleState(opts.checkpoint, opts.trustStore, state.Genesis.IdentityID)
		if externalErr != nil {
			return cliError(opts.jsonOut, "EXTERNAL_CHECKPOINT_INVALID", externalErr.Error(), 2)
		}
		relation, compareErr := identity.CompareLifecycleStates(state, external)
		if compareErr != nil {
			return cliError(opts.jsonOut, "LIFECYCLE_FORK", compareErr.Error()+"; do not sign from this home", 2)
		}
		freshness = relation
		if relation == "LOCAL_STALE" {
			return cliError(opts.jsonOut, "STALE_IDENTITY_STATE", "a newer authenticated lifecycle checkpoint exists; do not sign from this home - restore the current evidence home or establish a new identity if its ledger was lost", 2)
		}
	}
	result := map[string]any{
		"identity_id": state.Genesis.IdentityID, "advisory_label": state.Genesis.AdvisoryLabel,
		"lifecycle_sequence": state.LastSequence, "lifecycle_digest": state.LastRecordDigest,
		"active_epoch": activeEpoch, "active_operational_key_id": activeKey, "status": status,
		"pending_mutation":    state.PendingMutation,
		"identity_meaning":    "pseudonymous cryptographic continuity of one evidence ledger",
		"recovery_warning":    "If the recovery root is lost, lifecycle control cannot be restored. If it is compromised, establish a new independently pinned identity.",
		"lifecycle_freshness": freshness,
		"freshness_warning":   "Offline local state cannot prove that no newer lifecycle exists; compare a separately retained checkpoint.",
	}
	if opts.jsonOut {
		printJSON(result)
	} else {
		fmt.Printf("identity   %s\n", state.Genesis.IdentityID)
		fmt.Printf("label      %s (advisory only)\n", state.Genesis.AdvisoryLabel)
		fmt.Printf("lifecycle  %d %s\n", state.LastSequence, state.LastRecordDigest)
		fmt.Printf("status     %s\n", status)
		fmt.Printf("freshness  %s\n", freshness)
		if activeKey != "" {
			fmt.Printf("active     epoch %v, %s\n", activeEpoch, activeKey)
		}
		if state.PendingMutation {
			fmt.Println("recovery   REQUIRED: run ueg identity transaction-recover")
		}
		fmt.Println("warning    If the recovery root is lost, lifecycle control cannot be restored.")
		fmt.Println("           If it is compromised, establish a new independently pinned identity.")
		fmt.Println("           Offline local state cannot prove that no newer lifecycle exists.")
	}
	return 0
}

func identityRecoveryVerify(opts *identityOptions) int {
	if opts.recoveryPackage == "" || opts.identityID == "" {
		return identityUsageError(opts, "recovery-verify requires --recovery-package and --identity-id", "recovery-verify")
	}
	passphrase, err := readPassphrase(opts)
	if err != nil {
		return cliError(opts.jsonOut, "PASSPHRASE_UNAVAILABLE", err.Error(), 1)
	}
	defer wipe(passphrase)
	pkg, err := identity.VerifyRecoveryPackage(opts.recoveryPackage, passphrase, opts.identityID)
	if err != nil {
		return cliError(opts.jsonOut, "RECOVERY_PACKAGE_INVALID", err.Error(), 2)
	}
	if opts.jsonOut {
		printJSON(map[string]any{"valid": true, "identity_id": pkg.IdentityID, "recovery_root_key_id": pkg.RecoveryRootKeyID})
	} else {
		fmt.Printf("Recovery package verified for %s. The recovery signing self-test passed.\n", pkg.IdentityID)
	}
	return 0
}

func identityMutate(action string, opts *identityOptions) int {
	if opts.recoveryPackage == "" || opts.reason == "" {
		return identityUsageError(opts, action+" requires --recovery-package and --reason", action)
	}
	if !identity.IsBPlus(opts.home) {
		return cliError(opts.jsonOut, "BPLUS_IDENTITY_REQUIRED", "the selected evidence home is not a B+ identity", 1)
	}
	lock, err := ledger.AcquireHomeLock(opts.home, false)
	if err != nil || lock == nil {
		return cliError(opts.jsonOut, "EVIDENCE_BUSY", "cannot lock the evidence home: "+errorText(err), 1)
	}
	defer lock.Release()
	l, err := ledger.OpenReadOnly(opts.home)
	if err != nil {
		return cliError(opts.jsonOut, "EVIDENCE_VERIFICATION_FAILED", err.Error(), 2)
	}
	if bind := ledger.VerifyPetitions(l.Receipts(), l.Petitions()); !bind.OK {
		return cliError(opts.jsonOut, "EVIDENCE_VERIFICATION_FAILED", strings.Join(bind.Findings, "; "), 2)
	}
	state := l.IdentityState
	if code := requireCurrentLifecycleForMutation(opts, state); code != 0 {
		return code
	}
	var anchorDigest *string
	if opts.anchor != "" {
		anchor, anchorErr := loadKnownGoodAnchor(opts.anchor, state, l.Receipts())
		if anchorErr != nil {
			return cliError(opts.jsonOut, "KNOWN_GOOD_ANCHOR_INVALID", anchorErr.Error(), 2)
		}
		digest := anchor.AnchorDigest
		anchorDigest = &digest
	}
	if action == "revoke" {
		latest := state.Epochs[len(state.Epochs)-1]
		if !opts.confirmCompromise || opts.confirmKeyID != latest.OperationalKeyID {
			return identityUsageError(opts, "revoke requires --confirm-compromise and the exact current --confirm-key-id", "revoke")
		}
	}
	passphrase, err := readPassphrase(opts)
	if err != nil {
		return cliError(opts.jsonOut, "PASSPHRASE_UNAVAILABLE", err.Error(), 1)
	}
	defer wipe(passphrase)
	actionCode := map[string]string{
		"rotate": identity.ActionRotate, "transfer": identity.ActionRotate,
		"suspend": identity.ActionSuspend, "resume": identity.ActionResume,
		"recover": identity.ActionRecover, "revoke": identity.ActionRevoke,
	}[action]
	updated, record, err := identity.ApplyMutation(opts.home, opts.recoveryPackage, passphrase, identity.MutationRequest{
		Action: actionCode, ReasonCode: opts.reason, Boundary: l.Boundary(), EvidenceAnchorDigest: anchorDigest,
	})
	if err != nil {
		return cliError(opts.jsonOut, "IDENTITY_MUTATION_FAILED", err.Error(), 1)
	}
	extras := map[string]any{}
	if action == "recover" {
		extras["recovery_scope"] = "signing authority only; deleted evidence and a lost ledger are not restored"
	}
	printIdentityMutationResult(opts, strings.ToUpper(action), updated, record, extras)
	return 0
}

func requireCurrentLifecycleForMutation(opts *identityOptions, local *identity.State) int {
	if opts.checkpoint == "" && opts.trustStore == "" {
		return 0
	}
	if opts.checkpoint != "" && opts.trustStore != "" {
		return cliError(opts.jsonOut, "USAGE", "choose either --checkpoint or --trust-store", 1)
	}
	external, err := loadExternalLifecycleState(opts.checkpoint, opts.trustStore, local.Genesis.IdentityID)
	if err != nil {
		return cliError(opts.jsonOut, "EXTERNAL_CHECKPOINT_INVALID", err.Error(), 2)
	}
	relation, err := identity.CompareLifecycleStates(local, external)
	if err != nil {
		return cliError(opts.jsonOut, "LIFECYCLE_FORK", err.Error()+"; refusing lifecycle mutation", 2)
	}
	if relation == "LOCAL_STALE" {
		return cliError(opts.jsonOut, "STALE_IDENTITY_STATE", "a newer authenticated lifecycle exists; refusing lifecycle mutation from this stale home", 2)
	}
	return 0
}

func loadExternalLifecycleState(checkpointPath, trustStore, identityID string) (*identity.State, error) {
	if checkpointPath != "" {
		info, err := os.Lstat(checkpointPath)
		if err != nil {
			return nil, fmt.Errorf("inspect checkpoint: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 12*1024*1024 {
			return nil, fmt.Errorf("checkpoint must be a regular file no larger than 12 MiB")
		}
		raw, err := os.ReadFile(checkpointPath)
		if err != nil {
			return nil, err
		}
		checkpoint, state, err := identity.ParseLifecycleCheckpoint(raw)
		if err != nil {
			return nil, err
		}
		if checkpoint.IdentityID != identityID {
			return nil, fmt.Errorf("checkpoint does not match the selected evidence identity")
		}
		return state, nil
	}
	_, state, err := identity.LoadStoredCheckpoint(trustStore, identityID)
	return state, err
}

func loadKnownGoodAnchor(path string, state *identity.State, receipts []*ledger.Receipt) (*identity.EvidenceAnchor, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect known-good anchor: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1024*1024 {
		return nil, fmt.Errorf("known-good anchor must be a regular file no larger than 1 MiB")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	anchor, err := identity.ParseEvidenceAnchor(raw)
	if err != nil {
		return nil, err
	}
	if err := identity.ValidateEvidenceAnchor(anchor, state); err != nil {
		return nil, err
	}
	sequence := anchor.LedgerBoundary.SequenceNo
	if sequence < 0 || sequence >= len(receipts) || anchor.LedgerBoundary.ReceiptID == nil ||
		receipts[sequence].ReceiptID != *anchor.LedgerBoundary.ReceiptID {
		return nil, fmt.Errorf("known-good anchor does not match an exact receipt in the selected evidence home")
	}
	return anchor, nil
}

func identityExportArtifact(action string, opts *identityOptions) int {
	if opts.output == "" {
		return identityUsageError(opts, action+" requires --output", action)
	}
	lock, err := ledger.AcquireHomeLock(opts.home, false)
	if err != nil || lock == nil {
		return cliError(opts.jsonOut, "EVIDENCE_BUSY", "cannot lock the evidence home: "+errorText(err), 1)
	}
	defer lock.Release()
	var state *identity.State
	var value any
	var verify func([]byte) error
	switch action {
	case "card":
		state, err = identity.LoadPublic(opts.home)
		if err == nil {
			value, err = identity.NewIdentityCard(state)
			verify = func(raw []byte) error { _, parseErr := identity.ParseIdentityCard(raw); return parseErr }
		}
	case "checkpoint-export":
		state, err = identity.LoadPublic(opts.home)
		if err == nil {
			value, err = identity.NewLifecycleCheckpoint(state)
			verify = func(raw []byte) error { _, _, parseErr := identity.ParseLifecycleCheckpoint(raw); return parseErr }
		}
	case "anchor":
		var l *ledger.Ledger
		l, err = ledger.OpenReadOnlyWithPrivate(opts.home)
		if err == nil {
			state = l.IdentityState
			if bind := ledger.VerifyPetitions(l.Receipts(), l.Petitions()); !bind.OK {
				err = fmt.Errorf("stored requests failed verification: %s", strings.Join(bind.Findings, "; "))
			} else {
				value, err = identity.NewEvidenceAnchor(state, l.Boundary(), state.ActivePair)
				verify = func(raw []byte) error {
					anchor, parseErr := identity.ParseEvidenceAnchor(raw)
					if parseErr != nil {
						return parseErr
					}
					return identity.ValidateEvidenceAnchor(anchor, state)
				}
			}
		}
	}
	if err != nil {
		return cliError(opts.jsonOut, "IDENTITY_ARTIFACT_FAILED", err.Error(), 1)
	}
	if err := identity.WritePublicArtifact(opts.output, value, verify); err != nil {
		return cliError(opts.jsonOut, "IDENTITY_ARTIFACT_FAILED", err.Error(), 1)
	}
	if opts.jsonOut {
		printJSON(map[string]any{"written": opts.output, "artifact": action, "identity_id": state.Genesis.IdentityID})
	} else {
		fmt.Printf("Wrote %s for %s to %s. Retain it independently.\n", strings.ReplaceAll(action, "-", " "), state.Genesis.IdentityID, opts.output)
	}
	return 0
}

func identityImportCheckpoint(opts *identityOptions) int {
	if opts.input == "" || opts.trustStore == "" || opts.identityID == "" {
		return identityUsageError(opts, "checkpoint import requires --input, --trust-store, and --identity-id", "checkpoint-import")
	}
	raw, err := os.ReadFile(opts.input)
	if err != nil {
		return cliError(opts.jsonOut, "CHECKPOINT_IMPORT_FAILED", "cannot read checkpoint: "+err.Error(), 1)
	}
	result, err := identity.ImportCheckpoint(raw, opts.trustStore, opts.identityID)
	if err != nil {
		return cliError(opts.jsonOut, "CHECKPOINT_IMPORT_FAILED", err.Error(), 2)
	}
	if opts.jsonOut {
		printJSON(result)
	} else {
		fmt.Printf("Retained lifecycle checkpoint %d (%s) for %s.\n", result.Sequence, result.Digest, result.IdentityID)
	}
	return 0
}

func identityRecoverTransaction(opts *identityOptions) int {
	initializationPending, err := identity.InitializationPending(opts.home)
	if err != nil {
		return cliError(opts.jsonOut, "IDENTITY_RECOVERY_FAILED", err.Error(), 1)
	}
	if initializationPending {
		state, recoverErr := identity.RecoverPendingInitialization(opts.home, nil)
		if recoverErr != nil && !errors.Is(recoverErr, identity.ErrInitializationRolledBack) {
			return cliError(opts.jsonOut, "IDENTITY_RECOVERY_FAILED", recoverErr.Error(), 2)
		}
		rolledBack := errors.Is(recoverErr, identity.ErrInitializationRolledBack)
		if opts.jsonOut {
			result := map[string]any{"recovery_needed": true, "recovered": !rolledBack, "initialization_rolled_back": rolledBack}
			if state != nil {
				result["identity_id"] = state.Genesis.IdentityID
				result["lifecycle_sequence"] = state.LastSequence
			}
			printJSON(result)
		} else if rolledBack {
			fmt.Println("The interrupted initialization was rolled back. No evidence identity was created.")
		} else {
			fmt.Println("Initialization transaction recovery completed and the B+ identity verifies.")
		}
		return 0
	}
	lock, err := ledger.AcquireHomeLock(opts.home, false)
	if err != nil || lock == nil {
		return cliError(opts.jsonOut, "EVIDENCE_BUSY", "cannot lock the evidence home: "+errorText(err), 1)
	}
	defer lock.Release()
	migrationPending, err := identity.MigrationPending(opts.home)
	if err != nil {
		return cliError(opts.jsonOut, "IDENTITY_RECOVERY_FAILED", err.Error(), 1)
	}
	if migrationPending {
		state, recoverErr := identity.RecoverPendingMigration(opts.home)
		if recoverErr != nil && !errors.Is(recoverErr, identity.ErrMigrationRolledBack) {
			return cliError(opts.jsonOut, "IDENTITY_RECOVERY_FAILED", recoverErr.Error(), 2)
		}
		if opts.jsonOut {
			result := map[string]any{"recovery_needed": true, "recovered": recoverErr == nil, "migration_rolled_back": errors.Is(recoverErr, identity.ErrMigrationRolledBack)}
			if state != nil {
				result["identity_id"] = state.Genesis.IdentityID
				result["lifecycle_sequence"] = state.LastSequence
			}
			printJSON(result)
		} else if errors.Is(recoverErr, identity.ErrMigrationRolledBack) {
			fmt.Println("The interrupted migration was rolled back. Legacy evidence remains unchanged.")
		} else {
			fmt.Println("Migration transaction recovery completed and the B+ identity verifies.")
		}
		return 0
	}
	if !identity.IsBPlus(opts.home) {
		return cliError(opts.jsonOut, "BPLUS_IDENTITY_REQUIRED", "the selected evidence home is not a B+ identity and has no recoverable migration", 1)
	}
	pending, err := identity.MutationPending(opts.home)
	if err != nil {
		return cliError(opts.jsonOut, "IDENTITY_RECOVERY_FAILED", err.Error(), 1)
	}
	state, err := identity.RecoverPendingMutation(opts.home)
	if err != nil {
		return cliError(opts.jsonOut, "IDENTITY_RECOVERY_FAILED", err.Error(), 2)
	}
	if opts.jsonOut {
		printJSON(map[string]any{"recovery_needed": pending, "recovered": pending, "identity_id": state.Genesis.IdentityID, "lifecycle_sequence": state.LastSequence})
	} else if pending {
		fmt.Println("Lifecycle transaction recovery completed and the identity verifies.")
	} else {
		fmt.Println("No lifecycle transaction recovery was needed. The identity verifies.")
	}
	return 0
}

func identityMigrate(opts *identityOptions) int {
	if !opts.seen["home"] || opts.recoveryPackage == "" || opts.confirmKeyID == "" || !opts.confirmNotCompromised {
		return identityUsageError(opts, "migrate requires explicit --home, --recovery-package, --confirm-key-id, and --confirm-not-compromised", "migrate")
	}
	if identity.IsBPlus(opts.home) {
		return cliError(opts.jsonOut, "ALREADY_MIGRATED", "the selected evidence home is already B+", 1)
	}
	l, err := ledger.OpenReadOnlyWithPrivate(opts.home)
	if err != nil {
		return cliError(opts.jsonOut, "LEGACY_EVIDENCE_INVALID", err.Error(), 2)
	}
	if l.KeyID != opts.confirmKeyID {
		return cliError(opts.jsonOut, "LEGACY_KEY_CONFIRMATION_MISMATCH", "the independently confirmed key fingerprint does not match the legacy evidence home", 2)
	}
	chain := l.VerifyReceipts()
	bind := ledger.VerifyPetitions(l.Receipts(), l.Petitions())
	if !chain.OK || !bind.OK {
		return cliError(opts.jsonOut, "LEGACY_EVIDENCE_INVALID", strings.Join(append(chain.Findings, bind.Findings...), "; "), 2)
	}
	passphrase, err := readPassphrase(opts)
	if err != nil {
		return cliError(opts.jsonOut, "PASSPHRASE_UNAVAILABLE", err.Error(), 1)
	}
	defer wipe(passphrase)
	lock, err := ledger.AcquireHomeLock(opts.home, true)
	if err != nil || lock == nil {
		return cliError(opts.jsonOut, "EVIDENCE_BUSY", "cannot lock the legacy evidence home: "+errorText(err), 1)
	}
	defer lock.Release()
	state, err := identity.MigrateLegacy(opts.home, opts.recoveryPackage, passphrase, opts.label, opts.confirmKeyID, l.Boundary())
	if err != nil {
		return cliError(opts.jsonOut, "IDENTITY_MIGRATION_FAILED", err.Error(), 1)
	}
	printIdentityMutationResult(opts, "MIGRATED", state, state.Records[0], map[string]any{
		"recovery_package":              opts.recoveryPackage,
		"lifecycle_protection_began_at": l.Boundary(),
		"historical_note":               "historical evidence remains verifiable, but lifecycle protection did not exist before migration",
	})
	return 0
}

func readPassphrase(opts *identityOptions) ([]byte, error) {
	if opts.passphraseStdin {
		reader := bufio.NewReader(io.LimitReader(os.Stdin, 4097))
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("read passphrase from standard input: %w", err)
		}
		if len(line) > 4096 {
			return nil, fmt.Errorf("passphrase input exceeds 4096 bytes")
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("no interactive terminal is available; use --passphrase-stdin")
	}
	fmt.Fprint(os.Stderr, "Recovery package passphrase: ")
	secret, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read hidden passphrase: %w", err)
	}
	return secret, nil
}

func printIdentityMutationResult(opts *identityOptions, result string, state *identity.State, record *identity.LifecycleRecord, extras map[string]any) {
	output := map[string]any{
		"result": result, "identity_id": state.Genesis.IdentityID,
		"lifecycle_sequence": state.LastSequence, "lifecycle_digest": state.LastRecordDigest,
		"operational_status": record.OperationalStatus, "operational_key_id": record.OperationalKeyID,
		"epoch_number": record.EpochNumber,
	}
	for key, value := range extras {
		output[key] = value
	}
	if opts.jsonOut {
		printJSON(output)
		return
	}
	fmt.Printf("%s evidence identity %s\n", result, state.Genesis.IdentityID)
	fmt.Printf("  lifecycle  %d %s\n", state.LastSequence, state.LastRecordDigest)
	fmt.Printf("  epoch      %d %s %s\n", record.EpochNumber, record.OperationalStatus, record.OperationalKeyID)
	if result == "INITIALIZED" || result == "MIGRATED" {
		fmt.Printf("  recovery   %s (store offline; UEG created no hidden copy)\n", opts.recoveryPackage)
	}
}

func identityUsageError(opts *identityOptions, message, action string) int {
	if opts.jsonOut {
		return cliError(true, "USAGE", message, 1)
	}
	fmt.Fprintf(os.Stderr, "ueg: %s\n\n%s", message, identityCommandUsage[action])
	return 1
}

func wipe(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func errorText(err error) string {
	if err == nil {
		return "evidence-home lock is missing"
	}
	return err.Error()
}
