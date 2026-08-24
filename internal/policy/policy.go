// Package policy classifies a command by the kind of effect it can have and
// decides, under the active posture, whether that effect may proceed.
//
// The classification is deliberately syntactic: it reads the command line, not
// the program. It is therefore conservative — anything it cannot place is
// UNCLASSIFIED and, under enforce posture, refused. See docs/LIMITS.md.
package policy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
)

//go:embed rules.json
var rulesJSON []byte

// Class is how hard an effect is to take back.
type Class string

const (
	// Reversible: observing state, or a change this machine can undo exactly.
	Reversible Class = "REVERSIBLE"
	// Compensable: the effect stands, but a further action can make amends.
	Compensable Class = "COMPENSABLE"
	// Irrevocable: nothing after the fact restores the prior state.
	Irrevocable Class = "IRREVOCABLE"
	// Prohibited: irrevocable and catastrophic; no approval flag admits it.
	Prohibited Class = "PROHIBITED"
	// Unclassified: no rule matched, so UEG does not know. Fail closed.
	Unclassified Class = "UNCLASSIFIED"
)

// Posture is how UEG treats its own classification.
type Posture string

const (
	// Enforce: refuse what the classification says must not run.
	Enforce Posture = "enforce"
	// Observe: record the classification and do not gate non-prohibited
	// commands. PROHIBITED effects are still refused because they must never
	// start.
	Observe Posture = "observe"
)

// Outcome of an admission decision.
type Outcome string

const (
	Admitted Outcome = "ADMITTED"
	Refused  Outcome = "REFUSED"
)

type rule struct {
	ID            string   `json:"id"`
	Class         Class    `json:"class"`
	Surface       string   `json:"surface"`
	Cmd           []string `json:"cmd"`
	Subcmd        []string `json:"subcmd"`
	FlagsAny      []string `json:"flags_any"`
	FlagsAll      []string `json:"flags_all"`
	ArgsRegex     string   `json:"args_regex"`
	OperandIsRoot bool     `json:"operand_is_root"`
	Note          string   `json:"note"`

	compiled *regexp.Regexp
}

type ruleSet struct {
	Version        string  `json:"version"`
	UnmatchedClass Class   `json:"unmatched_class"`
	Rules          []*rule `json:"rules"`
}

var rules ruleSet

// RulesHash is the SHA-256 of the rule table, recorded in every receipt so a
// reader can tell which rules were in force.
var RulesHash string

func init() {
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		panic(fmt.Sprintf("policy: rules.json is invalid: %v", err))
	}
	for _, r := range rules.Rules {
		if r.ArgsRegex != "" {
			r.compiled = regexp.MustCompile(r.ArgsRegex)
		}
	}
	RulesHash = canon.SHA256Hex(rulesJSON)
}

// Classification is what the rule table says about one command.
type Classification struct {
	Class    Class  `json:"class"`
	RuleID   string `json:"rule_id"`
	Surface  string `json:"surface"`
	Reason   string `json:"reason"`
	Elevated bool   `json:"elevated"`
	// Argv after wrappers such as sudo or env assignments are removed.
	Effective []string `json:"effective_argv"`
}

var wrappers = map[string]bool{
	"sudo": true, "doas": true, "nice": true, "nohup": true,
	"time": true, "env": true, "stdbuf": true, "setsid": true,
}

var elevating = map[string]bool{"sudo": true, "doas": true, "runas": true}

// unwrap strips leading wrappers so `sudo rm -rf /` is classified as `rm -rf /`
// rather than as an unknown call to sudo.
func unwrap(argv []string) (effective []string, elevated bool) {
	elevated = false
	i := 0
	for i < len(argv) {
		base := executableBase(argv[i])
		if !wrappers[base] && !elevating[base] {
			break
		}
		if elevating[base] {
			elevated = true
		}
		i++
		// Skip wrapper-owned flags and VAR=value assignments.
		for i < len(argv) && (strings.HasPrefix(argv[i], "-") || strings.Contains(argv[i], "=") && !strings.HasPrefix(argv[i], "/")) {
			if strings.HasPrefix(argv[i], "-") && !isWrapperFlag(base, argv[i]) {
				break
			}
			i++
		}
	}
	if i >= len(argv) {
		return argv, elevated
	}
	return argv[i:], elevated
}

var executableSuffixes = []string{".exe", ".com", ".bat", ".cmd"}

// executableBase normalizes the executable spelling without resolving or
// opening it. UEG classifies argv syntactically, but Windows path separators,
// case, and PATHEXT aliases must not change a known command's policy class.
func executableBase(name string) string {
	name = strings.Trim(strings.TrimSpace(name), `"`)
	name = strings.ReplaceAll(name, `\`, "/")
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	name = strings.ToLower(name)
	for _, suffix := range executableSuffixes {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}
	return name
}

func isWrapperFlag(wrapper, flag string) bool {
	switch wrapper {
	case "sudo", "doas":
		return flag == "-E" || flag == "-H" || flag == "-n" || flag == "-S"
	case "nice":
		return strings.HasPrefix(flag, "-n")
	case "env":
		return flag == "-i" || flag == "-u"
	}
	return false
}

// splitArgs separates flags from operands and expands short flag clusters, so
// `-rf` satisfies a rule that asks for `-f`.
func splitArgs(args []string) (flags map[string]bool, operands []string) {
	flags = map[string]bool{}
	endOfFlags := false
	for _, a := range args {
		switch {
		case endOfFlags:
			operands = append(operands, a)
		case a == "--":
			endOfFlags = true
		case strings.HasPrefix(a, "--"):
			name := a
			if idx := strings.Index(a, "="); idx > 0 {
				name = a[:idx]
			}
			flags[name] = true
		case strings.HasPrefix(a, "-") && len(a) > 1:
			flags[a] = true
			for _, c := range a[1:] {
				flags["-"+string(c)] = true
			}
		default:
			operands = append(operands, a)
		}
	}
	return flags, operands
}

// rootLike reports whether an operand names a filesystem root, a home root, or
// a glob directly beneath one.
func rootLike(operand string) bool {
	raw := strings.Trim(strings.TrimSpace(operand), `"`)
	if raw == "~" || raw == "$HOME" || raw == "${HOME}" {
		return true
	}
	p := expandPercentEnvironment(raw)
	p = os.ExpandEnv(p)
	if p == "~" || strings.HasPrefix(p, `~\`) || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimLeft(p[1:], `\/`))
		}
	}
	if p == "" {
		return false
	}
	p = strings.Trim(strings.TrimSpace(p), `"`)
	p = stripWindowsDevicePrefix(p)
	p = strings.TrimRight(p, "*")
	if p == "" || p == "/" || p == `\` {
		return true // "/" or "/*"
	}
	if windowsRootLike(p) {
		return true
	}

	clean := filepath.Clean(p)
	switch filepath.ToSlash(clean) {
	case ".", "..", "/System", "/usr", "/etc", "/var", "/bin", "/boot", "/lib", "/home", "/root", "/Users":
		return true
	}

	if home, err := os.UserHomeDir(); err == nil && samePath(clean, filepath.Clean(home)) {
		return true
	}
	volume := filepath.VolumeName(clean)
	if volume != "" {
		remainder := strings.TrimPrefix(clean, volume)
		if remainder == "" || remainder == `\` || remainder == "/" || remainder == "." {
			return true
		}
		// A bare UNC share is a filesystem root even when Clean removes its
		// trailing separator.
		if strings.HasPrefix(volume, `\\`) && samePath(clean, volume) {
			return true
		}
	}
	return false
}

var percentEnvironment = regexp.MustCompile(`%([^%]+)%`)

func expandPercentEnvironment(value string) string {
	return percentEnvironment.ReplaceAllStringFunc(value, func(match string) string {
		name := match[1 : len(match)-1]
		if expanded, ok := os.LookupEnv(name); ok {
			return expanded
		}
		return match
	})
}

func stripWindowsDevicePrefix(value string) string {
	normalized := strings.ReplaceAll(value, `\`, "/")
	for _, prefix := range []string{"//?/UNC/", "//./UNC/"} {
		if len(normalized) >= len(prefix) && strings.EqualFold(normalized[:len(prefix)], prefix) {
			return "//" + normalized[len(prefix):]
		}
	}
	for _, prefix := range []string{"//?/", "//./"} {
		if strings.HasPrefix(normalized, prefix) {
			return normalized[len(prefix):]
		}
	}
	return value
}

func windowsRootLike(value string) bool {
	normalized := strings.ReplaceAll(value, `\`, "/")
	if len(normalized) >= 2 && normalized[1] == ':' && isASCIILetter(normalized[0]) {
		remainder := normalized[2:]
		if remainder == "" {
			return true
		}
		if !strings.HasPrefix(remainder, "/") {
			return false
		}
		return path.Clean("/"+strings.TrimLeft(remainder, "/")) == "/"
	}

	if strings.HasPrefix(normalized, "//") {
		clean := path.Clean("/" + strings.TrimLeft(normalized, "/"))
		parts := strings.Split(strings.Trim(clean, "/"), "/")
		return len(parts) <= 2
	}
	return false
}

func isASCIILetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// Classify places a command in an effect class.
func Classify(argv []string) Classification {
	if len(argv) == 0 {
		return Classification{Class: Unclassified, RuleID: "none", Surface: "process.spawn", Reason: "empty command", Effective: argv}
	}

	effective, elevated := unwrap(argv)
	base := executableBase(effective[0])
	args := effective[1:]
	flags, operands := splitArgs(args)
	joined := strings.Join(effective, " ")

	var sub string
	if len(operands) > 0 {
		sub = strings.ToLower(operands[0])
	}

	result := Classification{
		Class:     rules.UnmatchedClass,
		RuleID:    "unmatched",
		Surface:   "process.spawn",
		Reason:    "no rule in the table describes this command",
		Elevated:  elevated,
		Effective: effective,
	}

	for _, r := range rules.Rules {
		if !r.matches(base, sub, flags, operands, joined) {
			continue
		}
		result.Class = r.Class
		result.RuleID = r.ID
		result.Surface = r.Surface
		result.Reason = r.Note
		break
	}

	// Elevation raises the floor: running as another user turns a change this
	// account could undo into one it may not be able to.
	if elevated && (result.Class == Reversible || result.Class == Compensable) {
		result.Class = Irrevocable
		result.Reason = result.Reason + "; elevated with sudo/doas, so the prior state may not be restorable by this account"
		result.RuleID = result.RuleID + "+elevated"
	}

	return result
}

func (r *rule) matches(base, sub string, flags map[string]bool, operands []string, joined string) bool {
	// A rule with no command list is a pattern rule and must have a regex.
	if len(r.Cmd) > 0 && !contains(r.Cmd, base) {
		return false
	}
	if len(r.Cmd) == 0 && r.compiled == nil && len(r.FlagsAny) == 0 {
		return false
	}
	if len(r.Subcmd) > 0 && !contains(r.Subcmd, sub) {
		return false
	}
	if len(r.FlagsAny) > 0 && !anyFlag(flags, r.FlagsAny) {
		return false
	}
	for _, f := range r.FlagsAll {
		if !flags[f] {
			return false
		}
	}
	if r.compiled != nil && !r.compiled.MatchString(joined) {
		return false
	}
	if r.OperandIsRoot {
		found := false
		for _, o := range operands {
			if rootLike(o) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

func anyFlag(flags map[string]bool, want []string) bool {
	for _, f := range want {
		if flags[f] {
			return true
		}
	}
	return false
}

// Approvals records what the caller explicitly allowed for this invocation.
type Approvals struct {
	// Irrevocable effects were approved by the operator (--approve).
	Irrevocable bool
	// Unclassified commands were allowed to run (--allow-unclassified).
	Unclassified bool
}

// Decision is the admission result for one command.
type Decision struct {
	Outcome  Outcome `json:"outcome"`
	Reason   string  `json:"reason"`
	Posture  Posture `json:"posture"`
	Approval string  `json:"approval"`
	Class    Class   `json:"class"`
	RuleID   string  `json:"rule_id"`
}

// Decide applies the posture to a classification.
func Decide(c Classification, posture Posture, approvals Approvals) Decision {
	d := Decision{Outcome: Admitted, Posture: posture, Approval: "none", Class: c.Class, RuleID: c.RuleID}

	if c.Class == Prohibited {
		d.Outcome = Refused
		d.Reason = "prohibited effect: " + c.Reason
		return d
	}

	if posture == Observe {
		d.Reason = "observe posture: classification recorded; non-prohibited effect not gated"
		return d
	}

	switch c.Class {
	case Irrevocable:
		if approvals.Irrevocable {
			d.Approval = "operator"
			d.Reason = "irrevocable effect approved by operator"
		} else {
			d.Outcome = Refused
			d.Reason = "irrevocable effect requires --approve: " + c.Reason
		}
	case Unclassified:
		if approvals.Unclassified {
			d.Approval = "operator-unclassified"
			d.Reason = "unclassified command allowed by operator"
		} else {
			d.Outcome = Refused
			d.Reason = "unclassified command requires --allow-unclassified: " + c.Reason
		}
	case Compensable, Reversible:
		d.Reason = string(c.Class) + " effect admitted"
	default:
		d.Outcome = Refused
		d.Reason = "unknown effect class"
	}
	return d
}

// Snapshot is the policy identity hashed into every receipt: which rules, and
// which posture was actually in force.
func Snapshot(posture Posture, approvals Approvals) map[string]any {
	return map[string]any{
		"approval_irrevocable":  approvals.Irrevocable,
		"approval_unclassified": approvals.Unclassified,
		"posture":               string(posture),
		"rules_hash":            RulesHash,
		"rules_version":         rules.Version,
	}
}

// Hash returns the policy_hash for a posture and approval set.
func Hash(posture Posture, approvals Approvals) string {
	h, err := canon.HashJCS(Snapshot(posture, approvals))
	if err != nil {
		panic(err)
	}
	return h
}

// RuleCount is how many rules the table holds.
func RuleCount() int { return len(rules.Rules) }

// RulesVersion identifies the table.
func RulesVersion() string { return rules.Version }
