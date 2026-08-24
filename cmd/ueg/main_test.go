package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stevenkratushniak-ctrl/ueg/internal/identity"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
)

func TestInformationAndInvalidPathsDoNotCreateEvidence(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"root help", []string{"--help"}, 0},
		{"root version", []string{"--version"}, 0},
		{"root typo", []string{"not-a-command"}, 1},
		{"run help", []string{"run", "--help"}, 0},
		{"run help word", []string{"run", "help"}, 0},
		{"run missing", []string{"run"}, 1},
		{"run bad posture", []string{"run", "--posture", "bad", "--", "whoami"}, 1},
		{"check help", []string{"check", "--help"}, 0},
		{"identity help", []string{"identity", "--help"}, 0},
		{"identity init help", []string{"identity", "init", "--help"}, 0},
		{"identity migrate help", []string{"identity", "migrate", "--help"}, 0},
		{"identity status help", []string{"identity", "status", "--help"}, 0},
		{"identity recovery verify help", []string{"identity", "recovery-verify", "--help"}, 0},
		{"identity rotate help", []string{"identity", "rotate", "--help"}, 0},
		{"identity transfer help", []string{"identity", "transfer", "--help"}, 0},
		{"identity suspend help", []string{"identity", "suspend", "--help"}, 0},
		{"identity resume help", []string{"identity", "resume", "--help"}, 0},
		{"identity recover help", []string{"identity", "recover", "--help"}, 0},
		{"identity revoke help", []string{"identity", "revoke", "--help"}, 0},
		{"identity card help", []string{"identity", "card", "--help"}, 0},
		{"identity anchor help", []string{"identity", "anchor", "--help"}, 0},
		{"identity checkpoint help", []string{"identity", "checkpoint", "--help"}, 0},
		{"identity checkpoint export help", []string{"identity", "checkpoint", "export", "--help"}, 0},
		{"identity checkpoint import help", []string{"identity", "checkpoint", "import", "--help"}, 0},
		{"identity transaction recovery help", []string{"identity", "transaction-recover", "--help"}, 0},
		{"identity init missing", []string{"identity", "init", "--home", "missing"}, 1},
		{"identity unknown option", []string{"identity", "status", "--not-a-real-option"}, 1},
		{"replay missing", []string{"replay"}, 1},
		{"export help", []string{"export", "--help"}, 0},
		{"export missing", []string{"export"}, 1},
		{"verify help", []string{"verify", "--help"}, 0},
		{"verify invalid", []string{"verify", "missing.tar.gz"}, 2},
		{"ledger missing", []string{"ledger"}, 1},
		{"recover missing", []string{"recover"}, 1},
		{"policy help", []string{"policy", "--help"}, 0},
		{"validate missing", []string{"validate"}, 0},
		{"root validate alias", []string{"--validate"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "missing-home")
			t.Setenv("UEG_HOME", home)
			code := runSilently(t, tc.args)
			if code != tc.code {
				t.Fatalf("exit %d, want %d", code, tc.code)
			}
			if _, err := os.Stat(home); !os.IsNotExist(err) {
				t.Fatalf("information/error path created the evidence home: %v", err)
			}
		})
	}
}

func TestExistingHomeQueriesDoNotChangeFiles(t *testing.T) {
	home := filepath.Join(t.TempDir(), "evidence")
	t.Setenv("UEG_HOME", home)
	initializeBPlus(t, home)
	before := treeState(t, home)
	for _, args := range [][]string{
		{"ledger", "--json"},
		{"validate", "--json"},
		{"--validate", "--json"},
		{"recover", "--json"},
	} {
		if code := runSilently(t, args); code != 0 {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
	after := treeState(t, home)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("read-only commands changed the evidence home\nbefore=%v\nafter=%v", before, after)
	}
}

func TestCheckIsInertAndDoesNotCreateAReplayRecord(t *testing.T) {
	home := filepath.Join(t.TempDir(), "evidence")
	t.Setenv("UEG_HOME", home)
	initializeBPlus(t, home)
	before := treeState(t, home)
	if code := runSilently(t, []string{"check", "--", "git", "status"}); code != 0 {
		t.Fatalf("check: exit %d", code)
	}
	after := treeState(t, home)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("check changed the evidence home\nbefore=%v\nafter=%v", before, after)
	}
	if code := runSilently(t, []string{"replay", "--json"}); code == 0 {
		t.Fatal("an inert check unexpectedly created a replayable record")
	}
}

func TestUnknownCommandPointsToHelp(t *testing.T) {
	root := t.TempDir()
	t.Setenv("UEG_HOME", filepath.Join(root, "missing-home"))
	code, stderr := runCapturedStderr(t, []string{"rnu"})
	if code != 1 {
		t.Fatalf("unknown command exit %d, want 1", code)
	}
	if !strings.Contains(stderr, "ueg --help") {
		t.Fatalf("unknown command did not provide a Help next action: %q", stderr)
	}
}

func TestLedgerReturnsNonzeroWhileRecoveryIsPending(t *testing.T) {
	home := filepath.Join(t.TempDir(), "evidence")
	t.Setenv("UEG_HOME", home)
	initializeBPlus(t, home)
	if code := runSilently(t, []string{"run", "--", "git", "status"}); code != 0 {
		t.Fatalf("record setup command: exit %d", code)
	}
	receiptLine := lastNonemptyLine(t, filepath.Join(home, "receipts.ndjson"))
	petitionLine := lastNonemptyLine(t, filepath.Join(home, "petitions.ndjson"))
	pending, err := json.Marshal(map[string]string{
		"receipt_line":  receiptLine,
		"petition_line": petitionLine,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ueg.pending.json"), append(pending, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runSilently(t, []string{"ledger", "--json"}); code != 2 {
		t.Fatalf("ledger with pending recovery returned exit %d, want 2", code)
	}
}

func TestTamperedBPlusHomeReplayDoesNotChangeFiles(t *testing.T) {
	home := filepath.Join(t.TempDir(), "evidence")
	t.Setenv("UEG_HOME", home)
	initializeBPlus(t, home)
	if code := runSilently(t, []string{"run", "--", "git", "status"}); code != 0 {
		t.Fatalf("record setup command: exit %d", code)
	}
	receiptsPath := filepath.Join(home, "receipts.ndjson")
	data, err := os.ReadFile(receiptsPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), "ueg:cli:", "tampered:cli:", 1)
	if tampered == string(data) {
		t.Fatal("test setup did not find the signed actor field")
	}
	if err := os.WriteFile(receiptsPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	before := treeState(t, home)
	if code := runSilently(t, []string{"replay"}); code == 0 {
		t.Fatal("tampered replay unexpectedly succeeded")
	}
	after := treeState(t, home)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("failed replay changed the evidence home\nbefore=%v\nafter=%v", before, after)
	}
}

func TestNewerCheckpointStopsStaleCloneBeforeExecutionOrMutation(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current")
	recovery := initializeBPlus(t, current)
	stale := filepath.Join(root, "stale")
	copyTree(t, current, stale)

	l, err := ledger.OpenReadOnly(current)
	if err != nil {
		t.Fatal(err)
	}
	advanced, _, err := identity.ApplyMutation(current, recovery, []byte("test-only recovery passphrase"), identity.MutationRequest{
		Action: identity.ActionRotate, ReasonCode: "STALE_CLONE_TEST", Boundary: l.Boundary(),
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := identity.NewLifecycleCheckpoint(advanced)
	if err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(root, "newer-checkpoint.json")
	if err := identity.WritePublicArtifact(checkpointPath, checkpoint, func(raw []byte) error {
		_, _, parseErr := identity.ParseLifecycleCheckpoint(raw)
		return parseErr
	}); err != nil {
		t.Fatal(err)
	}

	before := treeState(t, stale)
	if code := runSilently(t, []string{"run", "--home", stale, "--checkpoint", checkpointPath, "--", "git", "status"}); code != 2 {
		t.Fatalf("stale clone run exit %d, want 2", code)
	}
	if code := runSilently(t, []string{"identity", "status", "--home", stale, "--checkpoint", checkpointPath, "--json"}); code != 2 {
		t.Fatalf("stale clone status exit %d, want 2", code)
	}
	after := treeState(t, stale)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("stale-state refusal changed the clone\nbefore=%v\nafter=%v", before, after)
	}
}

func initializeBPlus(t *testing.T, home string) string {
	t.Helper()
	recoveryDir := filepath.Join(filepath.Dir(home), "offline")
	if err := os.MkdirAll(recoveryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	recovery := filepath.Join(recoveryDir, filepath.Base(home)+"-recovery.json")
	if _, err := identity.Initialize(home, recovery, []byte("test-only recovery passphrase"), "test identity"); err != nil {
		t.Fatalf("initialize B+ test identity: %v", err)
	}
	return recovery
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

type fileState struct {
	Path    string
	Size    int64
	ModTime time.Time
	SHA256  string
}

func treeState(t *testing.T, root string) []fileState {
	t.Helper()
	var out []fileState
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, fileState{
			Path: relative, Size: info.Size(), ModTime: info.ModTime(), SHA256: fmt.Sprintf("%x", sum),
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func runSilently(t *testing.T, args []string) int {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errRead, errWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = outWrite, errWrite
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(io.Discard, outRead); done <- struct{}{} }()
	go func() { _, _ = io.Copy(io.Discard, errRead); done <- struct{}{} }()
	code := run(args)
	_ = outWrite.Close()
	_ = errWrite.Close()
	<-done
	<-done
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = outRead.Close()
	_ = errRead.Close()
	return code
}

func runCapturedStderr(t *testing.T, args []string) (int, string) {
	t.Helper()
	oldErr := os.Stderr
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = write
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(read)
		done <- string(data)
	}()
	code := run(args)
	_ = write.Close()
	stderr := <-done
	os.Stderr = oldErr
	_ = read.Close()
	return code, stderr
}

func lastNonemptyLine(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[len(lines)-1]) == "" {
		t.Fatalf("no record found in %s", path)
	}
	return lines[len(lines)-1]
}
