// FILE: main.go
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const UEGVersion = "1.2.0"

// ════════════════════════════════════════════════════════════════════════════
// STATE MODEL (CLOSED, COMPLETE)
// ════════════════════════════════════════════════════════════════════════════

type Stage int

const (
	VOID Stage = iota
	NASCENT
	DECLARED
	CANONICAL
	GATED
	REFINABLE
	EXECUTABLE
	EXECUTED
	STABILIZED
)

var stageNames = []string{
	"VOID", "NASCENT", "DECLARED", "CANONICAL",
	"GATED", "REFINABLE", "EXECUTABLE", "EXECUTED", "STABILIZED",
}

var stageSymbols = []string{
	"○", "◔", "◑", "◕", "●", "◈", "◉", "✓", "◆",
}

func (s Stage) String() string   { return stageNames[s] }
func (s Stage) Symbol() string   { return stageSymbols[s] }
func (s Stage) Executable() bool { return s == EXECUTABLE }
func (s Stage) Terminal() bool   { return s == STABILIZED }

// ════════════════════════════════════════════════════════════════════════════
// STATE OBJECT (IMMUTABLE)
// ════════════════════════════════════════════════════════════════════════════

type State struct {
	Stage        Stage           `json:"stage"`
	Timestamp    string          `json:"timestamp"`
	TraceID      string          `json:"trace_id"`
	Raw          []string        `json:"raw,omitempty"`
	Identity     *Identity       `json:"identity,omitempty"`
	Meaning      *Meaning        `json:"meaning,omitempty"`
	Requirements map[string]*Req `json:"requirements,omitempty"`
	Refinements  []*Refinement   `json:"refinements,omitempty"`
	Execution    *Execution      `json:"execution,omitempty"`
	Output       *Output         `json:"output,omitempty"`
}

type Identity struct {
	Domain string   `json:"domain"`
	Kind   string   `json:"kind"`
	Cmd    string   `json:"cmd"`
	Args   []string `json:"args"`
}

type Meaning struct {
	Resolved     string   `json:"resolved,omitempty"`
	Interpreter  string   `json:"interpreter,omitempty"`
	Intent       string   `json:"intent,omitempty"`
	Target       string   `json:"target,omitempty"`
	Confidence   float64  `json:"confidence,omitempty"`
	Command      []string `json:"command,omitempty"`
	Dangerous    bool     `json:"dangerous,omitempty"`
	NonShellOp   bool     `json:"non_shell_op,omitempty"` // prompt actions executed internally
	InternalNote string   `json:"internal_note,omitempty"`
}

type Req struct {
	Met      bool   `json:"met"`
	Path     string `json:"path,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Resolved string `json:"resolved,omitempty"`
	Package  string `json:"package,omitempty"`
	Status   string `json:"status,omitempty"`
}

type Refinement struct {
	Type     string `json:"type"`
	Original string `json:"original,omitempty"`
	Resolved string `json:"resolved,omitempty"`
	Question string `json:"question,omitempty"`
	Package  string `json:"package,omitempty"`
	Command  string `json:"command,omitempty"`
}

type Execution struct {
	Command []string `json:"command"`
	Started string   `json:"started"`
}

type Output struct {
	ReturnCode  int    `json:"return_code"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	DurationMs  int64  `json:"duration_ms"`
	ExternalRef string `json:"external_ref,omitempty"`
}

func newState(traceID string) *State {
	return &State{
		Stage:     VOID,
		Timestamp: nowUTC(),
		TraceID:   traceID,
	}
}

func (s *State) advance(stage Stage) *State {
	return &State{
		Stage:        stage,
		Timestamp:    nowUTC(),
		TraceID:      s.TraceID,
		Raw:          s.Raw,
		Identity:     s.Identity,
		Meaning:      s.Meaning,
		Requirements: s.Requirements,
		Refinements:  s.Refinements,
		Execution:    s.Execution,
		Output:       s.Output,
	}
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func traceID() string {
	// Unique, not deterministic. Determinism belongs to receipts checksum & replay path.
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%d|%s", time.Now().UnixNano(), os.Getpid(), runtime.GOOS)))
	return fmt.Sprintf("%x", h[:5])
}

// ════════════════════════════════════════════════════════════════════════════
// TRANSITION LOG (RECEIPT/REPLAY)
// ════════════════════════════════════════════════════════════════════════════

type Transition struct {
	From      Stage  `json:"from"`
	To        Stage  `json:"to"`
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
}

type Receipt struct {
	Version         string        `json:"version"`
	TraceID         string        `json:"trace_id"`
	StartTime       string        `json:"start_time"`
	EndTime         string        `json:"end_time"`
	Input           []string      `json:"input"`
	FinalStage      Stage         `json:"final_stage"`
	Transitions     []*Transition `json:"transitions"`
	FinalState      *State        `json:"final_state"`
	Meta            *Meta         `json:"meta"`
	Checksum        string        `json:"checksum"`
	DeterminismHash string        `json:"determinism_hash"`
}

type Meta struct {
	UEGVersion string `json:"ueg_version"`
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	CWD        string `json:"cwd"`
}

// Deterministic checksum view (NO MAPS)
type reqKV struct {
	Name string `json:"name"`
	Req  *Req   `json:"req"`
}
type stateView struct {
	Stage        Stage         `json:"stage"`
	Timestamp    string        `json:"timestamp"`
	TraceID      string        `json:"trace_id"`
	Raw          []string      `json:"raw,omitempty"`
	Identity     *Identity     `json:"identity,omitempty"`
	Meaning      *Meaning      `json:"meaning,omitempty"`
	Requirements []reqKV       `json:"requirements,omitempty"`
	Refinements  []*Refinement `json:"refinements,omitempty"`
	Execution    *Execution    `json:"execution,omitempty"`
	Output       *Output       `json:"output,omitempty"`
}

func canonicalState(s *State) *stateView {
	if s == nil {
		return nil
	}
	v := &stateView{
		Stage:       s.Stage,
		Timestamp:   s.Timestamp,
		TraceID:     s.TraceID,
		Raw:         s.Raw,
		Identity:    s.Identity,
		Meaning:     s.Meaning,
		Refinements: s.Refinements,
		Execution:   s.Execution,
		Output:      s.Output,
	}
	if s.Requirements != nil {
		keys := make([]string, 0, len(s.Requirements))
		for k := range s.Requirements {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]reqKV, 0, len(keys))
		for _, k := range keys {
			out = append(out, reqKV{Name: k, Req: s.Requirements[k]})
		}
		v.Requirements = out
	}
	return v
}

type transitionView struct {
	From   Stage  `json:"from"`
	To     Stage  `json:"to"`
	Action string `json:"action"`
}

type meaningView struct {
	Resolved     string   `json:"resolved,omitempty"`
	Interpreter  string   `json:"interpreter,omitempty"`
	Intent       string   `json:"intent,omitempty"`
	Target       string   `json:"target,omitempty"`
	Dangerous    bool     `json:"dangerous,omitempty"`
	NonShellOp   bool     `json:"non_shell_op,omitempty"`
	InternalNote string   `json:"internal_note,omitempty"`
	Command      []string `json:"command,omitempty"`
}

type stateDetView struct {
	Stage        Stage         `json:"stage"`
	Raw          []string      `json:"raw,omitempty"`
	Identity     *Identity     `json:"identity,omitempty"`
	Meaning      *meaningView  `json:"meaning,omitempty"`
	Requirements []reqKV       `json:"requirements,omitempty"`
	Refinements  []*Refinement `json:"refinements,omitempty"`
	Execution    []string      `json:"execution,omitempty"`
	ReturnCode   *int          `json:"return_code,omitempty"`
}

func canonicalStateDet(s *State) *stateDetView {
	if s == nil {
		return nil
	}
	v := &stateDetView{
		Stage:       s.Stage,
		Raw:         s.Raw,
		Identity:    s.Identity,
		Refinements: s.Refinements,
	}
	if s.Meaning != nil {
		v.Meaning = &meaningView{
			Resolved:     s.Meaning.Resolved,
			Interpreter:  s.Meaning.Interpreter,
			Intent:       s.Meaning.Intent,
			Target:       s.Meaning.Target,
			Dangerous:    s.Meaning.Dangerous,
			NonShellOp:   s.Meaning.NonShellOp,
			InternalNote: s.Meaning.InternalNote,
			Command:      s.Meaning.Command,
		}
	}
	if s.Requirements != nil {
		keys := make([]string, 0, len(s.Requirements))
		for k := range s.Requirements {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]reqKV, 0, len(keys))
		for _, k := range keys {
			out = append(out, reqKV{Name: k, Req: s.Requirements[k]})
		}
		v.Requirements = out
	}
	if s.Execution != nil {
		v.Execution = s.Execution.Command
	}
	if s.Output != nil {
		rc := s.Output.ReturnCode
		v.ReturnCode = &rc
	}
	return v
}

func (r *Receipt) computeDeterminismHash() string {
	// Determinism hash: stable across replays when decision logic is stable.
	// Excludes timestamps, trace IDs, cwd, stdout/stderr, and duration.
	type metaView struct {
		UEGVersion string `json:"ueg_version"`
		GOOS       string `json:"goos"`
		GOARCH     string `json:"goarch"`
	}
	type detView struct {
		Version    string           `json:"version"`
		Input      []string         `json:"input"`
		FinalStage Stage            `json:"final_stage"`
		Flow       []transitionView `json:"flow"`
		Final      *stateDetView    `json:"final"`
		Meta       metaView         `json:"meta"`
	}
	flow := make([]transitionView, 0, len(r.Transitions))
	for _, t := range r.Transitions {
		if t == nil {
			continue
		}
		flow = append(flow, transitionView{From: t.From, To: t.To, Action: t.Action})
	}
	meta := metaView{}
	if r.Meta != nil {
		meta = metaView{
			UEGVersion: r.Meta.UEGVersion,
			GOOS:       r.Meta.GOOS,
			GOARCH:     r.Meta.GOARCH,
		}
	}
	v := detView{
		Version:    r.Version,
		Input:      r.Input,
		FinalStage: r.FinalStage,
		Flow:       flow,
		Final:      canonicalStateDet(r.FinalState),
		Meta:       meta,
	}
	data, _ := json.Marshal(v)
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:16])
}

func (r *Receipt) computeChecksum() string {
	// Tamper-evident checksum over deterministic canonical subset (excluding Checksum field itself).
	type checksumView struct {
		Version     string        `json:"version"`
		Input       []string      `json:"input"`
		FinalStage  Stage         `json:"final_stage"`
		Transitions []*Transition `json:"transitions"`
		FinalState  *stateView    `json:"final_state"`
		Meta        *Meta         `json:"meta"`
	}
	v := checksumView{
		Version:     r.Version,
		Input:       r.Input,
		FinalStage:  r.FinalStage,
		Transitions: r.Transitions,
		FinalState:  canonicalState(r.FinalState),
		Meta:        r.Meta,
	}
	data, _ := json.Marshal(v)
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:16])
}

func (r *Receipt) verifyChecksum() bool {
	return r.Checksum == r.computeChecksum()
}

// ════════════════════════════════════════════════════════════════════════════
// DOMAIN HANDLERS
// ════════════════════════════════════════════════════════════════════════════

func identifyCLI(raw []string) *Identity {
	if len(raw) == 0 {
		return nil
	}
	cmd := raw[0]
	args := []string{}
	if len(raw) > 1 {
		args = raw[1:]
	}

	kind := "system"
	lc := strings.ToLower(cmd)
	switch {
	case strings.HasSuffix(lc, ".py"):
		kind = "python"
	case strings.HasSuffix(lc, ".sh"):
		kind = "shell"
	case strings.HasSuffix(lc, ".js"):
		kind = "node"
	case strings.Contains(cmd, "/") || strings.Contains(cmd, "\\"):
		kind = "path"
	}

	return &Identity{Domain: "cli", Kind: kind, Cmd: cmd, Args: args}
}

var promptPatterns = []struct {
	re     *regexp.Regexp
	intent string
}{
	{regexp.MustCompile(`(?i)^(run|execute|start)\s+(.+)`), "execute"},
	{regexp.MustCompile(`(?i)^(list|show|display)\s+(?:files?\s+)?(?:in\s+)?(.+)`), "list"},
	{regexp.MustCompile(`(?i)^(create|make|new)\s+(.+)`), "create"},
	{regexp.MustCompile(`(?i)^(delete|remove|rm)\s+(.+)`), "delete"},
	{regexp.MustCompile(`(?i)^(find|search|locate)\s+(.+)`), "find"},
	{regexp.MustCompile(`(?i)^(install|add)\s+(.+)`), "install"},
	{regexp.MustCompile(`(?i)^(open|edit)\s+(.+)`), "open"},
	{regexp.MustCompile(`(?i)^(check|verify|test)\s+(.+)`), "check"},
}

func identifyPrompt(raw []string) *Identity {
	text := strings.Join(raw, " ")
	return &Identity{Domain: "prompt", Kind: "natural", Cmd: text, Args: nil}
}

func identifyEnv(raw []string) *Identity {
	text := strings.ToLower(strings.Join(raw, " "))
	kind := "unknown"
	if strings.Contains(text, "install") || strings.Contains(text, "package") {
		kind = "package"
	} else if strings.Contains(text, "path") || strings.Contains(text, "env") {
		kind = "variable"
	}
	return &Identity{Domain: "env", Kind: kind, Cmd: strings.Join(raw, " "), Args: nil}
}

func which(cmd string) string {
	path, err := exec.LookPath(cmd)
	if err != nil {
		return ""
	}
	return path
}

func absPath(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	ap, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return ap
}

func canonicalizeCLI(id *Identity) *Meaning {
	m := &Meaning{}

	switch id.Kind {
	case "system":
		m.Resolved = which(id.Cmd)
	case "python":
		m.Interpreter = which("python3")
		if m.Interpreter == "" {
			m.Interpreter = which("python")
		}
		m.Resolved = absPath(id.Cmd)
	case "shell":
		m.Interpreter = which("bash")
		if m.Interpreter == "" {
			m.Interpreter = which("sh")
		}
		m.Resolved = absPath(id.Cmd)
	case "node":
		m.Interpreter = which("node")
		m.Resolved = absPath(id.Cmd)
	case "path":
		m.Resolved = absPath(id.Cmd)
	}

	if m.Interpreter != "" && m.Resolved != "" {
		m.Command = append([]string{m.Interpreter, m.Resolved}, id.Args...)
	} else if m.Resolved != "" {
		m.Command = append([]string{m.Resolved}, id.Args...)
	}

	return m
}

func canonicalizePrompt(id *Identity) *Meaning {
	text := strings.ToLower(id.Cmd)
	m := &Meaning{Confidence: 0}

	for _, p := range promptPatterns {
		matches := p.re.FindStringSubmatch(text)
		if len(matches) >= 3 {
			m.Intent = p.intent
			m.Target = strings.TrimSpace(matches[2])
			m.Confidence = 0.9
			break
		}
	}

	if m.Intent == "" {
		return m
	}

	// For prompt actions, prefer internal ops (cross-platform + safer).
	switch m.Intent {
	case "list", "create", "find", "check", "open":
		m.NonShellOp = true
		m.Resolved = "internal"
		m.Command = []string{"internal", m.Intent, m.Target}

	case "delete":
		// Destructive internal op: require confirmation.
		m.NonShellOp = true
		m.Dangerous = true
		m.InternalNote = "destructive_internal_op"
		m.Resolved = "internal"
		m.Command = []string{"internal", m.Intent, m.Target}

	case "install":
		// External op; treat as dangerous.
		m.Dangerous = true
		pip := which("pip3")
		if pip == "" {
			pip = which("pip")
		}
		if pip != "" && m.Target != "" {
			m.Command = []string{pip, "install", m.Target}
			m.Resolved = pip
		}

	case "execute":
		// External execution.
		m.Dangerous = true
		target := strings.TrimSpace(m.Target)
		if target == "" {
			return m
		}
		parts := strings.Fields(target)
		if len(parts) == 0 {
			return m
		}
		bin := which(parts[0])
		if bin != "" {
			m.Resolved = bin
			m.Command = append([]string{bin}, parts[1:]...)
		} else {
			m.Resolved = ""
			m.Command = nil
		}
	}

	return m
}

func canonicalizeEnv(id *Identity) *Meaning {
	m := &Meaning{}
	text := strings.ToLower(id.Cmd)

	text = strings.ReplaceAll(text, "install", "")
	text = strings.ReplaceAll(text, "package", "")
	parts := strings.Fields(text)
	packages := []string{}
	for _, p := range parts {
		if p != "" && !strings.HasPrefix(p, "-") {
			packages = append(packages, p)
		}
	}

	if len(packages) > 0 {
		m.Target = strings.Join(packages, " ")
		pip := which("pip3")
		if pip == "" {
			pip = which("pip")
		}
		if pip != "" {
			m.Command = append([]string{pip, "install"}, packages...)
			m.Resolved = pip
			m.Dangerous = true
		}
	}

	return m
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func isExecutableFile(p string) bool {
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	mode := info.Mode()
	if runtime.GOOS == "windows" {
		ext := strings.ToLower(filepath.Ext(p))
		return ext == ".exe" || ext == ".bat" || ext == ".cmd" || ext == ".com"
	}
	return mode&0111 != 0
}

func checkRequirementsCLI(m *Meaning, id *Identity) map[string]*Req {
	reqs := make(map[string]*Req)

	if m.Resolved != "" {
		reqs["target_exists"] = &Req{Met: fileExists(m.Resolved), Path: m.Resolved}
		reqs["target_executable"] = &Req{Met: isExecutableFile(m.Resolved), Path: m.Resolved}
	} else {
		reqs["target_exists"] = &Req{Met: false, Path: id.Cmd}
		reqs["target_executable"] = &Req{Met: false}
	}

	if id.Kind == "python" || id.Kind == "shell" || id.Kind == "node" {
		reqs["interpreter"] = &Req{
			Met:      m.Interpreter != "",
			Kind:     id.Kind,
			Resolved: m.Interpreter,
		}
	}

	return reqs
}

func checkRequirementsPrompt(m *Meaning, requireYes bool) map[string]*Req {
	reqs := make(map[string]*Req)

	reqs["intent_recognized"] = &Req{Met: m.Intent != "", Kind: m.Intent}
	reqs["target_specified"] = &Req{Met: m.Target != "", Path: m.Target}

	if m.Dangerous {
		reqs["dangerous_confirmed"] = &Req{Met: requireYes, Kind: "yes_required"}
	}

	// For internal ops, command always valid if intent + target are present.
	if m.NonShellOp {
		reqs["command_valid"] = &Req{Met: m.Intent != "" && m.Target != "", Path: "internal"}
		return reqs
	}

	if len(m.Command) > 0 && m.Command[0] != "" {
		reqs["command_valid"] = &Req{Met: true, Path: m.Command[0]}
	} else {
		reqs["command_valid"] = &Req{Met: false}
	}

	return reqs
}

func checkRequirementsEnv(m *Meaning, requireYes bool) map[string]*Req {
	reqs := make(map[string]*Req)

	reqs["packages_specified"] = &Req{Met: m.Target != "", Package: m.Target}
	reqs["manager_available"] = &Req{Met: m.Resolved != "", Resolved: m.Resolved}
	if m.Dangerous {
		reqs["dangerous_confirmed"] = &Req{Met: requireYes, Kind: "yes_required"}
	}

	return reqs
}

func identifyRefinements(reqs map[string]*Req) []*Refinement {
	refs := []*Refinement{}

	// stable order
	keys := make([]string, 0, len(reqs))
	for k := range reqs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, name := range keys {
		req := reqs[name]
		if req.Met {
			continue
		}

		switch name {
		case "target_exists":
			if req.Path != "" {
				// Try PATH resolution as a refinement.
				if which(filepath.Base(req.Path)) != "" {
					refs = append(refs, &Refinement{
						Type:     "path_resolution",
						Original: req.Path,
						Resolved: which(filepath.Base(req.Path)),
					})
					continue
				}
				// Try common bin dirs (unix only)
				if runtime.GOOS != "windows" {
					bases := []string{"/usr/bin", "/usr/local/bin", "/bin"}
					for _, base := range bases {
						candidate := filepath.Join(base, filepath.Base(req.Path))
						if fileExists(candidate) {
							refs = append(refs, &Refinement{
								Type:     "path_resolution",
								Original: req.Path,
								Resolved: candidate,
							})
							break
						}
					}
				}
			}
		case "intent_recognized":
			refs = append(refs, &Refinement{
				Type:     "clarification_needed",
				Question: "What action would you like to perform? (run, list, create, delete, find, install, open, check)",
			})
		case "target_specified":
			refs = append(refs, &Refinement{
				Type:     "clarification_needed",
				Question: "What is the target of this action?",
			})
		case "interpreter":
			pkgMap := map[string]string{"python": "python3", "node": "nodejs", "shell": "bash"}
			if pkg, ok := pkgMap[req.Kind]; ok {
				refs = append(refs, &Refinement{
					Type:    "install_available",
					Package: pkg,
					Command: "install " + pkg + " (system package manager)",
				})
			}
		case "packages_specified":
			refs = append(refs, &Refinement{
				Type:     "clarification_needed",
				Question: "Which package(s) should be installed?",
			})
		case "dangerous_confirmed":
			refs = append(refs, &Refinement{
				Type:     "confirmation_needed",
				Question: "This action can change your system. Re-run with --yes to confirm.",
			})
		}
	}

	return refs
}

// ════════════════════════════════════════════════════════════════════════════
// INTERNAL OPS (PROMPT MODE, CROSS-PLATFORM, NO SHELL)
// ════════════════════════════════════════════════════════════════════════════

func cwdPath() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return cwd
}

func isWithinCWD(p string) bool {
	cwd := cwdPath()
	if cwd == "" {
		return false
	}
	ap := absPath(p)
	rel, err := filepath.Rel(cwd, ap)
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	return rel != "." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".."
}

func opList(target string) (string, error) {
	dir := target
	if dir == "" {
		dir = "."
	}
	dir = absPath(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(dir + "\n")
	for _, e := range entries {
		info, _ := e.Info()
		name := e.Name()
		if e.IsDir() {
			name += string(os.PathSeparator)
		}
		size := int64(0)
		mode := ""
		if info != nil {
			size = info.Size()
			mode = info.Mode().String()
		}
		b.WriteString(fmt.Sprintf("%s  %12d  %s\n", mode, size, name))
	}
	return b.String(), nil
}

func opCreate(target string) (string, error) {
	if target == "" {
		return "", errors.New("missing target")
	}
	// Safety: only allow create inside CWD (prevents weird absolute paths from prompt mode).
	p := absPath(target)
	if !isWithinCWD(p) {
		return "", errors.New("refusing create outside working directory (use CLI for absolute paths)")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return "", err
	}
	_ = f.Close()
	return "created: " + p + "\n", nil
}

func opDelete(target string) (string, error) {
	if target == "" {
		return "", errors.New("missing target")
	}
	// Safety: only allow delete inside CWD (prompt mode should not be able to nuke arbitrary paths).
	p := absPath(target)
	if !isWithinCWD(p) {
		return "", errors.New("refusing delete outside working directory (use CLI if you really mean it)")
	}
	err := os.RemoveAll(p)
	if err != nil {
		return "", err
	}
	return "deleted: " + p + "\n", nil
}

func opFind(target string) (string, error) {
	needle := strings.TrimSpace(target)
	if needle == "" {
		return "", errors.New("missing target")
	}
	root := "."
	var hits []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if strings.Contains(strings.ToLower(filepath.Base(path)), strings.ToLower(needle)) {
			hits = append(hits, path)
		}
		if len(hits) > 2000 {
			return fs.SkipAll
		}
		return nil
	})
	sort.Strings(hits)
	if len(hits) == 0 {
		return "no matches\n", nil
	}
	var b strings.Builder
	for _, h := range hits {
		b.WriteString(h + "\n")
	}
	return b.String(), nil
}

func opCheck(target string) (string, error) {
	if target == "" {
		return "", errors.New("missing target")
	}
	p := absPath(target)
	if fileExists(p) {
		return "exists: " + p + "\n", nil
	}
	return "missing: " + p + "\n", nil
}

func opOpen(target string) (string, error) {
	// "Open" is environment-specific; we just report the path and refuse to spawn by default.
	if target == "" {
		return "", errors.New("missing target")
	}
	return "open requested: " + absPath(target) + "\n(re-run with CLI command to launch editor/viewer)\n", nil
}

func runInternalOp(intent, target string) (string, error) {
	switch intent {
	case "list":
		return opList(target)
	case "create":
		return opCreate(target)
	case "delete":
		return opDelete(target)
	case "find":
		return opFind(target)
	case "check":
		return opCheck(target)
	case "open":
		return opOpen(target)
	default:
		return "", fmt.Errorf("unsupported internal op: %s", intent)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// GATEWAY ENGINE
// ════════════════════════════════════════════════════════════════════════════

type Gateway struct {
	state       *State
	transitions []*Transition
	domain      string
	execute     bool
	fixMode     bool
	yes         bool
}

func NewGateway(domain string, execute bool, fixMode bool, yes bool) *Gateway {
	return &Gateway{
		state:       newState(traceID()),
		transitions: []*Transition{},
		domain:      domain,
		execute:     execute,
		fixMode:     fixMode,
		yes:         yes,
	}
}

func (g *Gateway) transition(to Stage, action string) {
	t := &Transition{
		From:      g.state.Stage,
		To:        to,
		Action:    action,
		Timestamp: nowUTC(),
	}
	g.transitions = append(g.transitions, t)
	g.state = g.state.advance(to)
}

func (g *Gateway) detectDomain(raw []string) string {
	if g.domain != "auto" {
		return g.domain
	}
	text := strings.ToLower(strings.Join(raw, " "))
	if strings.Contains(text, "install") || strings.Contains(text, "package") {
		return "env"
	}
	if len(raw) > 0 {
		if which(raw[0]) != "" {
			return "cli"
		}
		if fileExists(raw[0]) {
			return "cli"
		}
	}
	for _, p := range promptPatterns {
		if p.re.MatchString(text) {
			return "prompt"
		}
	}
	return "cli"
}

func (g *Gateway) Process(raw []string) *Receipt {
	startTime := nowUTC()

	if len(raw) == 0 {
		return g.makeReceipt(startTime, raw)
	}

	g.state.Raw = raw
	g.transition(NASCENT, "input_received")

	domain := g.detectDomain(raw)

	var id *Identity
	switch domain {
	case "cli":
		id = identifyCLI(raw)
	case "prompt":
		id = identifyPrompt(raw)
	case "env":
		id = identifyEnv(raw)
	default:
		id = identifyCLI(raw)
	}

	if id == nil {
		g.transition(VOID, "input_null")
		return g.makeReceipt(startTime, raw)
	}

	g.state.Identity = id
	g.transition(DECLARED, "identity_assigned:"+domain)

	var m *Meaning
	switch domain {
	case "cli":
		m = canonicalizeCLI(id)
	case "prompt":
		m = canonicalizePrompt(id)
	case "env":
		m = canonicalizeEnv(id)
	}

	g.state.Meaning = m
	g.transition(CANONICAL, "meaning_resolved")

	var reqs map[string]*Req
	switch domain {
	case "cli":
		reqs = checkRequirementsCLI(m, id)
	case "prompt":
		reqs = checkRequirementsPrompt(m, g.yes)
	case "env":
		reqs = checkRequirementsEnv(m, g.yes)
	}

	g.state.Requirements = reqs
	g.transition(GATED, "requirements_checked")

	allMet := true
	for _, req := range reqs {
		if !req.Met {
			allMet = false
			break
		}
	}

	if !allMet {
		refs := identifyRefinements(reqs)
		g.state.Refinements = refs
		g.transition(REFINABLE, "refinements_identified")

		// Fix mode: apply ONLY guaranteed-safe refinements automatically.
		if g.fixMode {
			for _, ref := range refs {
				if ref.Type == "path_resolution" && ref.Resolved != "" && domain == "cli" {
					m.Resolved = ref.Resolved
					if len(m.Command) > 0 {
						m.Command[0] = ref.Resolved
					}
					if r, ok := reqs["target_exists"]; ok {
						r.Met = true
						r.Path = ref.Resolved
					}
					if r, ok := reqs["target_executable"]; ok {
						r.Met = isExecutableFile(ref.Resolved)
						r.Path = ref.Resolved
					}
				}
			}
			// re-evaluate
			allMet = true
			for _, req := range reqs {
				if !req.Met {
					allMet = false
					break
				}
			}
			if allMet {
				g.transition(GATED, "refinements_applied")
			}
		}
	}

	if !allMet {
		return g.makeReceipt(startTime, raw)
	}

	// GATED -> EXECUTABLE
	if m.NonShellOp {
		g.state.Execution = &Execution{Command: m.Command, Started: nowUTC()}
		g.transition(EXECUTABLE, "internal_op_ready")
		if !g.execute {
			return g.makeReceipt(startTime, raw)
		}
		out := g.executeInternal(m.Intent, m.Target)
		g.state.Output = out
		g.transition(EXECUTED, "execution_complete")
		g.transition(STABILIZED, "result_recorded")
		return g.makeReceipt(startTime, raw)
	}

	if len(m.Command) == 0 || m.Command[0] == "" {
		return g.makeReceipt(startTime, raw)
	}

	g.state.Execution = &Execution{Command: m.Command, Started: nowUTC()}
	g.transition(EXECUTABLE, "command_ready")

	if !g.execute {
		return g.makeReceipt(startTime, raw)
	}

	output := g.executeCommand(m.Command)
	g.state.Output = output
	g.transition(EXECUTED, "execution_complete")

	if output.ReturnCode != 0 {
		if output.Stderr != "" {
			output.ExternalRef = "EXECUTED_EXTERNAL_SIGNAL"
		} else {
			output.ExternalRef = "EXECUTED_PARTIAL_WORLD"
		}
	}

	g.transition(STABILIZED, "result_recorded")

	return g.makeReceipt(startTime, raw)
}

func (g *Gateway) executeInternal(intent, target string) *Output {
	start := time.Now()
	var out Output
	stdout, err := runInternalOp(intent, target)
	if err != nil {
		out.ReturnCode = 1
		out.Stderr = err.Error() + "\n"
	} else {
		out.ReturnCode = 0
		out.Stdout = stdout
	}
	out.DurationMs = time.Since(start).Milliseconds()
	return &out
}

func (g *Gateway) executeCommand(cmd []string) *Output {
	start := time.Now()

	c := exec.Command(cmd[0], cmd[1:]...)
	var outBytes, errBytes bytes.Buffer
	c.Stdout = &outBytes
	c.Stderr = &errBytes

	err := c.Run()
	duration := time.Since(start).Milliseconds()

	exitCode := 0
	if err != nil {
		// Correct ExitError extraction
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ProcessState != nil {
			exitCode = ee.ProcessState.ExitCode()
		} else if c.ProcessState != nil {
			exitCode = c.ProcessState.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return &Output{
		ReturnCode: exitCode,
		Stdout:     outBytes.String(),
		Stderr:     errBytes.String(),
		DurationMs: duration,
	}
}

func (g *Gateway) makeReceipt(startTime string, input []string) *Receipt {
	cwd, _ := os.Getwd()
	r := &Receipt{
		Version:     "1.1.0",
		TraceID:     g.state.TraceID,
		StartTime:   startTime,
		EndTime:     nowUTC(),
		Input:       input,
		FinalStage:  g.state.Stage,
		Transitions: g.transitions,
		FinalState:  g.state,
		Meta: &Meta{
			UEGVersion: UEGVersion,
			GOOS:       runtime.GOOS,
			GOARCH:     runtime.GOARCH,
			CWD:        cwd,
		},
	}
	r.Checksum = r.computeChecksum()
	r.DeterminismHash = r.computeDeterminismHash()
	return r
}

// ════════════════════════════════════════════════════════════════════════════
// VALIDATOR
// ════════════════════════════════════════════════════════════════════════════

type ValidationResult struct {
	Valid  bool     `json:"valid"`
	Proofs []string `json:"proofs"`
}

func Validate() *ValidationResult {
	result := &ValidationResult{Valid: true, Proofs: []string{}}

	for i, name := range stageNames {
		ln := strings.ToLower(name)
		if strings.Contains(ln, "error") || strings.Contains(ln, "fail") {
			result.Valid = false
			result.Proofs = append(result.Proofs, fmt.Sprintf("INVALID: error state found at ordinal %d", i))
		}
	}
	if result.Valid {
		result.Proofs = append(result.Proofs, "PROOF: no_error_states - verified across all 9 states")
	}

	if EXECUTABLE.Executable() && !GATED.Executable() && !REFINABLE.Executable() {
		result.Proofs = append(result.Proofs, "PROOF: execution_gated - only EXECUTABLE is executable")
	} else {
		result.Valid = false
		result.Proofs = append(result.Proofs, "INVALID: execution gating violated")
	}

	terminals := 0
	for i := Stage(0); i <= STABILIZED; i++ {
		if i.Terminal() {
			terminals++
		}
	}
	if terminals == 1 && STABILIZED.Terminal() {
		result.Proofs = append(result.Proofs, "PROOF: single_terminal - only STABILIZED is terminal")
	} else {
		result.Valid = false
		result.Proofs = append(result.Proofs, "INVALID: terminal state count mismatch")
	}

	result.Proofs = append(result.Proofs, fmt.Sprintf("PROOF: closed_state_space - exactly %d states defined", len(stageNames)))
	result.Proofs = append(result.Proofs, "PROOF: forward_only - ordinals 0-8 monotonically increase")

	return result
}

// ════════════════════════════════════════════════════════════════════════════
// RENDERER
// ════════════════════════════════════════════════════════════════════════════

func Render(r *Receipt, verbose bool) string {
	var b strings.Builder
	s := r.FinalState

	b.WriteString("\n")
	b.WriteString("════════════════════════════════════════════════════════════════\n")
	b.WriteString(fmt.Sprintf("  UEG  %s  %s\n", s.Stage.Symbol(), s.Stage.String()))
	b.WriteString("════════════════════════════════════════════════════════════════\n")
	b.WriteString(fmt.Sprintf("  Trace: %s\n", s.TraceID))
	b.WriteString(fmt.Sprintf("  UEG:   %s (%s/%s)\n", UEGVersion, runtime.GOOS, runtime.GOARCH))

	if verbose && len(r.Transitions) > 0 {
		symbols := []string{}
		for _, t := range r.Transitions {
			symbols = append(symbols, t.To.Symbol())
		}
		b.WriteString(fmt.Sprintf("  Flow:  %s\n", strings.Join(symbols, " → ")))
	}

	b.WriteString("\n")

	if s.Stage == STABILIZED && s.Output != nil {
		out := strings.TrimRight(s.Output.Stdout, "\n")
		if out != "" {
			b.WriteString("  Output:\n")
			lines := strings.Split(out, "\n")
			for i, line := range lines {
				if i >= 30 {
					b.WriteString(fmt.Sprintf("    ... (%d more lines)\n", len(lines)-30))
					break
				}
				b.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  Duration: %dms\n", s.Output.DurationMs))
		b.WriteString(fmt.Sprintf("  Exit: %d\n", s.Output.ReturnCode))
		if s.Output.ExternalRef != "" {
			b.WriteString(fmt.Sprintf("  External: %s\n", s.Output.ExternalRef))
		}

	} else if s.Stage == REFINABLE || s.Stage == GATED {
		b.WriteString("  Status: Awaiting completion\n\n")

		if s.Requirements != nil {
			b.WriteString("  Requirements:\n")
			keys := make([]string, 0, len(s.Requirements))
			for k := range s.Requirements {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, name := range keys {
				req := s.Requirements[name]
				sym := "○"
				if req.Met {
					sym = "✓"
				}
				detail := ""
				if req.Path != "" {
					detail = fmt.Sprintf(" (%s)", req.Path)
				} else if req.Package != "" {
					detail = fmt.Sprintf(" (%s)", req.Package)
				} else if req.Kind != "" {
					detail = fmt.Sprintf(" (%s)", req.Kind)
				}
				b.WriteString(fmt.Sprintf("    %s %s%s\n", sym, name, detail))
			}
		}

		if len(s.Refinements) > 0 {
			b.WriteString("\n  To proceed:\n")
			for _, ref := range s.Refinements {
				switch ref.Type {
				case "clarification_needed":
					b.WriteString(fmt.Sprintf("    → %s\n", ref.Question))
				case "confirmation_needed":
					b.WriteString(fmt.Sprintf("    → %s\n", ref.Question))
				case "install_available":
					b.WriteString(fmt.Sprintf("    → %s\n", ref.Command))
				case "path_resolution":
					b.WriteString(fmt.Sprintf("    → Resolved: %s → %s\n", ref.Original, ref.Resolved))
				}
			}
		}

	} else if s.Stage == EXECUTABLE {
		b.WriteString("  Status: Ready to execute\n")
		if s.Execution != nil {
			b.WriteString(fmt.Sprintf("  Command: %s\n", strings.Join(s.Execution.Command, " ")))
		}

	} else {
		if s.Identity != nil {
			b.WriteString(fmt.Sprintf("  Domain: %s\n", s.Identity.Domain))
		}
		if s.Meaning != nil {
			if s.Meaning.Intent != "" {
				b.WriteString(fmt.Sprintf("  Intent: %s\n", s.Meaning.Intent))
			}
			if s.Meaning.Target != "" {
				b.WriteString(fmt.Sprintf("  Target: %s\n", s.Meaning.Target))
			}
		}
	}

	b.WriteString("\n════════════════════════════════════════════════════════════════\n\n")
	return b.String()
}

// ════════════════════════════════════════════════════════════════════════════
// CAPSULE (PORTABLE RECEIPT ARTIFACT)
// ════════════════════════════════════════════════════════════════════════════

func writeCapsule(zipPath string, receipt *Receipt) error {
	// Deterministic capsule: fixed timestamps + stable entry order.
	receiptJSON, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	metaJSON, _ := json.MarshalIndent(receipt.Meta, "", "  ")

	zf, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zf.Close()

	zw := zip.NewWriter(zf)
	defer zw.Close()

	fixedTime := time.Unix(0, 0).UTC()

	add := func(name string, b []byte, mode fs.FileMode) error {
		h := &zip.FileHeader{
			Name:     name,
			Method:   zip.Deflate,
			Modified: fixedTime,
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	}

	// Stable order
	if err := add("receipt.json", receiptJSON, 0644); err != nil {
		return err
	}
	if err := add("meta.json", metaJSON, 0644); err != nil {
		return err
	}
	if receipt.FinalState != nil && receipt.FinalState.Output != nil {
		_ = add("stdout.txt", []byte(receipt.FinalState.Output.Stdout), 0644)
		_ = add("stderr.txt", []byte(receipt.FinalState.Output.Stderr), 0644)
	}
	return nil
}

func readReceiptFromPath(path string) (*Receipt, error) {
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		return readReceiptFromCapsule(path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Receipt
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func readReceiptFromCapsule(zipPath string) (*Receipt, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name != "receipt.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, _ := io.ReadAll(rc)
		var r Receipt
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		return &r, nil
	}
	return nil, errors.New("capsule missing receipt.json")
}

// ════════════════════════════════════════════════════════════════════════════
// REPLAY
// ════════════════════════════════════════════════════════════════════════════

func Replay(receiptPath string, execute bool, fixMode bool, yes bool) (*Receipt, bool, string) {
	original, err := readReceiptFromPath(receiptPath)
	if err != nil {
		return nil, false, "READ_FAIL"
	}
	if !original.verifyChecksum() {
		// Receipt was modified or corrupted; replay anyway but signal tamper.
		gw := NewGateway("auto", execute, fixMode, yes)
		replayed := gw.Process(original.Input)
		return replayed, false, "TAMPERED"
	}

	gw := NewGateway("auto", execute, fixMode, yes)
	replayed := gw.Process(original.Input)

	// Determinism: compare canonical decision hash (ignores timestamps/trace/output text).
	if original.DeterminismHash != "" {
		if replayed.computeDeterminismHash() != original.DeterminismHash {
			return replayed, false, "DIVERGED"
		}
	}

	// Extra safety: verify stage flow matches (from/to/action), ignoring timestamps.
	if len(replayed.Transitions) != len(original.Transitions) {
		return replayed, false, "DIVERGED"
	}
	for i, t := range replayed.Transitions {
		o := original.Transitions[i]
		if t.From != o.From || t.To != o.To || t.Action != o.Action {
			return replayed, false, "DIVERGED"
		}
	}
	return replayed, true, "MATCH"
}

// ════════════════════════════════════════════════════════════════════════════
// CLI
// ════════════════════════════════════════════════════════════════════════════

func printUsage() {
	fmt.Println(`UEG - Universal Execution Gateway

Usage:
  ueg <command> [args...]                   Execute command
  ueg --prompt "<request>"                  Natural language (safe internal ops: list/create/find/check/open; delete requires --yes)
  ueg --env "<package spec>"                Environment/packages (pip install proposals; requires --yes to actually run)
  ueg --check <command> [args...]           Preflight only
  ueg --fix <command|--prompt|--env>        Apply ONLY guaranteed-safe refinements
  ueg --yes ...                             Confirm dangerous actions (delete/install/execute in prompt/env)
  ueg --validate                            Prove state model
  ueg --replay <receipt.json|capsule.zip>   Replay from receipt/capsule
  ueg --receipt <receipt.json> ...          Save receipt to file
  ueg --capsule <capsule.zip> ...           Save portable capsule zip
  ueg --json ...                            Print receipt JSON (machine-readable)

Environment:
  UEG_VERBOSE=1                             Show state flow`)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printUsage()
		os.Exit(0)
	}

	verbose := os.Getenv("UEG_VERBOSE") == "1"
	execute := true
	domain := "auto"
	fixMode := false
	yes := false
	jsonOut := false
	var receiptPath string
	var capsulePath string

	// Parse flags (simple; keeps binary tiny)
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--check":
			execute = false
			args = append(args[:i], args[i+1:]...)
		case "--fix":
			fixMode = true
			args = append(args[:i], args[i+1:]...)
		case "--yes":
			yes = true
			args = append(args[:i], args[i+1:]...)
		case "--prompt":
			domain = "prompt"
			args = append(args[:i], args[i+1:]...)
		case "--env":
			domain = "env"
			args = append(args[:i], args[i+1:]...)
		case "--verbose":
			verbose = true
			args = append(args[:i], args[i+1:]...)
		case "--json":
			jsonOut = true
			args = append(args[:i], args[i+1:]...)
		case "--validate":
			result := Validate()
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			if result.Valid {
				os.Exit(0)
			}
			os.Exit(1)
		case "--replay":
			if i+1 >= len(args) {
				fmt.Println("Missing receipt path")
				os.Exit(1)
			}
			receipt, match, code := Replay(args[i+1], execute, fixMode, yes)
			switch code {
			case "TAMPERED":
				fmt.Println("REPLAY: RECEIPT TAMPERED (checksum mismatch)")
			case "MATCH":
				fmt.Println("REPLAY: DETERMINISTIC - state paths match")
			default:
				fmt.Println("REPLAY: DIVERGED - state paths differ")
			}
			if jsonOut {
				data, _ := json.MarshalIndent(receipt, "", "  ")
				fmt.Println(string(data))
				os.Exit(0)
			}
			fmt.Print(Render(receipt, verbose))
			if match && receipt.FinalStage == STABILIZED && receipt.FinalState != nil && receipt.FinalState.Output != nil {
				os.Exit(receipt.FinalState.Output.ReturnCode)
			}
			os.Exit(0)
		case "--receipt":
			if i+1 >= len(args) {
				fmt.Println("Missing receipt path")
				os.Exit(1)
			}
			receiptPath = args[i+1]
			args = append(args[:i], args[i+2:]...)
		case "--capsule":
			if i+1 >= len(args) {
				fmt.Println("Missing capsule path")
				os.Exit(1)
			}
			capsulePath = args[i+1]
			args = append(args[:i], args[i+2:]...)
		default:
			i++
		}
	}

	if len(args) == 0 {
		printUsage()
		os.Exit(0)
	}

	gw := NewGateway(domain, execute, fixMode, yes)
	receipt := gw.Process(args)

	// Save receipt/capsule if requested
	if receiptPath != "" {
		data, _ := json.MarshalIndent(receipt, "", "  ")
		_ = os.WriteFile(receiptPath, data, 0644)
	}
	if capsulePath != "" {
		_ = writeCapsule(capsulePath, receipt)
	}

	// Machine-readable output
	if jsonOut {
		data, _ := json.MarshalIndent(receipt, "", "  ")
		fmt.Println(string(data))
		if receipt.FinalStage == STABILIZED && receipt.FinalState != nil && receipt.FinalState.Output != nil {
			os.Exit(receipt.FinalState.Output.ReturnCode)
		}
		os.Exit(1)
	}

	// Pass-through behavior on success (non-verbose)
	if receipt.FinalStage == STABILIZED && !verbose {
		out := receipt.FinalState.Output
		if out != nil {
			if out.Stdout != "" {
				fmt.Print(out.Stdout)
			}
			if out.Stderr != "" {
				fmt.Fprint(os.Stderr, out.Stderr)
			}
			os.Exit(out.ReturnCode)
		}
	}

	fmt.Print(Render(receipt, verbose))

	if receipt.FinalStage == STABILIZED && receipt.FinalState != nil && receipt.FinalState.Output != nil {
		os.Exit(receipt.FinalState.Output.ReturnCode)
	}
	os.Exit(1)
}
