package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func classOf(t *testing.T, argv ...string) Classification {
	t.Helper()
	return Classify(argv)
}

func TestDangerousCommandsAreProhibited(t *testing.T) {
	cases := [][]string{
		{"rm", "-rf", "/"},
		{"rm", "-rf", "/*"},
		{"sudo", "rm", "-rf", "/"},
		{"mkfs.ext4", "/dev/sda1"},
		{"dd", "if=/dev/zero", "of=/dev/sda"},
		{"chmod", "-R", "777", "/"},
	}
	for _, argv := range cases {
		c := classOf(t, argv...)
		if c.Class != Prohibited {
			t.Errorf("%v classified %s (rule %s), want PROHIBITED", argv, c.Class, c.RuleID)
		}
	}
}

func TestWindowsExecutableAliasesDoNotChangeKnownClassification(t *testing.T) {
	cases := [][]string{
		{`C:\\Windows\\System32\\FORMAT.COM`, "C:"},
		{`c:/windows/system32/DiskPart.ExE`, "/s", "script.txt"},
		{`C:\\tools\\rm.CMD`, "-rf", `C:\\`},
		{`RM.BAT`, "-rf", `C:\\`},
	}
	for _, argv := range cases {
		c := classOf(t, argv...)
		if c.Class != Prohibited {
			t.Errorf("%v classified %s (rule %s), want PROHIBITED", argv, c.Class, c.RuleID)
		}
	}
}

func TestEquivalentRootSpellingsAreProhibited(t *testing.T) {
	t.Setenv("UEG_TEST_DRIVE", "C:")
	cases := []string{
		`C:\\`,
		`c:/`,
		`C:\\.`,
		`C:\\folder\\..`,
		`\\?\C:\\`,
		`\\.\C:\\`,
		`\\server\share\`,
		`\\server\share\folder\..`,
		`\\?\UNC\server\share\`,
		`\\.\UNC\server\share\`,
		`%UEG_TEST_DRIVE%\\`,
	}
	for _, operand := range cases {
		c := classOf(t, "rm.exe", "-rf", operand)
		if c.Class != Prohibited {
			t.Errorf("root alias %q classified %s (rule %s), want PROHIBITED", operand, c.Class, c.RuleID)
		}
	}
	for _, operand := range []string{"$HOME", "${HOME}"} {
		c := classOf(t, "rm", "-rf", operand)
		if c.Class != Prohibited {
			t.Errorf("literal home alias %q classified %s, want PROHIBITED", operand, c.Class)
		}
	}

	home, err := os.UserHomeDir()
	if err == nil {
		for _, operand := range []string{"~", home, filepath.Join(home, ".")} {
			if c := classOf(t, "rm", "-rf", operand); c.Class != Prohibited {
				t.Errorf("home alias %q classified %s, want PROHIBITED", operand, c.Class)
			}
		}
	}
}

func TestProhibitedAliasesStayRefusedUnderEveryMode(t *testing.T) {
	c := classOf(t, `C:\\Windows\\System32\\FORMAT.COM`, `%SystemDrive%\\`)
	if c.Class != Prohibited {
		t.Fatalf("format alias classified %s, want PROHIBITED", c.Class)
	}
	for _, posture := range []Posture{Enforce, Observe} {
		for _, approvals := range []Approvals{{}, {Irrevocable: true}, {Unclassified: true}, {Irrevocable: true, Unclassified: true}} {
			if d := Decide(c, posture, approvals); d.Outcome != Refused {
				t.Fatalf("%s admitted prohibited alias with approvals %+v", posture, approvals)
			}
		}
	}
}

func TestNonRootWindowsPathsAreNotProhibitedAsRoots(t *testing.T) {
	cases := []string{
		`C:folder`,
		`C:\folder`,
		`C:\folder\child`,
		`\\server\share\folder`,
		`\\?\C:\folder`,
		`\\?\UNC\server\share\folder`,
	}
	for _, operand := range cases {
		c := classOf(t, "rm.exe", "-rf", operand)
		if c.Class == Prohibited {
			t.Errorf("non-root path %q classified PROHIBITED (rule %s)", operand, c.RuleID)
		}
	}
}

func TestHelpFlagCannotBypassCommandPolicy(t *testing.T) {
	cases := [][]string{
		{"sh", "-c", "printf owned", "--help"},
		{"rm", "-rf", "/", "--help"},
		{"some-unknown-tool", "--help"},
	}
	want := []Class{Unclassified, Prohibited, Unclassified}
	for i, argv := range cases {
		c := classOf(t, argv...)
		if c.Class != want[i] {
			t.Errorf("%v classified %s (rule %s), want %s", argv, c.Class, c.RuleID, want[i])
		}
	}
}

func TestDoubleDashEndsFlagParsing(t *testing.T) {
	c := classOf(t, "rm", "--", "--help")
	if c.Class != Irrevocable {
		t.Fatalf("rm -- --help classified %s (rule %s), want IRREVOCABLE", c.Class, c.RuleID)
	}
}

func TestAmbiguousMutatingFormsFailClosed(t *testing.T) {
	cases := [][]string{
		{"find", ".", "-delete"},
		{"date", "--set", "2030-01-01"},
		{"git", "branch", "-D", "main"},
		{"git", "remote", "remove", "origin"},
		{"git", "config", "--global", "user.name", "Other"},
	}
	for _, argv := range cases {
		c := classOf(t, argv...)
		if c.Class != Unclassified {
			t.Errorf("%v classified %s (rule %s), want UNCLASSIFIED", argv, c.Class, c.RuleID)
		}
	}
}

func TestOverwriteCapableFileCommandsRequireIrrevocableApproval(t *testing.T) {
	for _, argv := range [][]string{
		{"cp", "source", "destination"},
		{"mv", "source", "destination"},
		{"tee", "destination"},
		{"rsync", "source", "destination"},
		{"unzip", "archive.zip"},
	} {
		c := classOf(t, argv...)
		if c.Class != Irrevocable {
			t.Errorf("%v classified %s (rule %s), want IRREVOCABLE", argv, c.Class, c.RuleID)
		}
	}
}

// No enforce-mode approval combination admits a prohibited effect. The path is
// removed, not guarded.
func TestProhibitedIsRefusedUnderEnforceWithEveryApprovalCombination(t *testing.T) {
	c := classOf(t, "rm", "-rf", "/")
	for _, approvals := range []Approvals{
		{},
		{Irrevocable: true},
		{Unclassified: true},
		{Irrevocable: true, Unclassified: true},
	} {
		d := Decide(c, Enforce, approvals)
		if d.Outcome != Refused {
			t.Fatalf("rm -rf / was %s with approvals %+v; it must stay refused", d.Outcome, approvals)
		}
		if d.Approval != "none" {
			t.Fatalf("prohibited effect recorded approval %q with approvals %+v", d.Approval, approvals)
		}
	}
}

func TestProhibitedIsRefusedUnderObserve(t *testing.T) {
	c := classOf(t, "rm", "-rf", "/")
	for _, approvals := range []Approvals{
		{},
		{Irrevocable: true},
		{Unclassified: true},
		{Irrevocable: true, Unclassified: true},
	} {
		d := Decide(c, Observe, approvals)
		if d.Outcome != Refused {
			t.Fatalf("observe posture admitted PROHIBITED with approvals %+v: %+v", approvals, d)
		}
	}
}

func TestIrrevocableNeedsApproval(t *testing.T) {
	c := classOf(t, "git", "push", "--force")
	if c.Class != Irrevocable {
		t.Fatalf("git push --force classified %s, want IRREVOCABLE", c.Class)
	}
	if d := Decide(c, Enforce, Approvals{}); d.Outcome != Refused {
		t.Fatal("an irrevocable effect was admitted without approval")
	}
	d := Decide(c, Enforce, Approvals{Irrevocable: true})
	if d.Outcome != Admitted || d.Approval != "operator" {
		t.Fatalf("approval did not admit the effect: %+v", d)
	}
}

func TestUnknownCommandsFailClosed(t *testing.T) {
	c := classOf(t, "some-binary-nobody-has-heard-of", "--go")
	if c.Class != Unclassified {
		t.Fatalf("unknown command classified %s, want UNCLASSIFIED", c.Class)
	}
	if d := Decide(c, Enforce, Approvals{}); d.Outcome != Refused {
		t.Fatal("an unclassified command was admitted under enforce posture")
	}
	if d := Decide(c, Enforce, Approvals{Unclassified: true}); d.Outcome != Admitted {
		t.Fatal("--allow-unclassified did not admit the command")
	}
}

func TestReadOnlyCommandsRun(t *testing.T) {
	for _, argv := range [][]string{
		{"echo", "hello"},
		{"ls", "-la"},
		{"git", "status"},
		{"cat", "/etc/hostname"},
	} {
		c := classOf(t, argv...)
		if c.Class != Reversible {
			t.Errorf("%v classified %s (rule %s), want REVERSIBLE", argv, c.Class, c.RuleID)
		}
		if d := Decide(c, Enforce, Approvals{}); d.Outcome != Admitted {
			t.Errorf("%v was refused: %s", argv, d.Reason)
		}
	}
}

// sudo must not hide the command behind it.
func TestElevationIsUnwrappedAndRaisesTheFloor(t *testing.T) {
	c := classOf(t, "sudo", "mkdir", "a")
	if !c.Elevated {
		t.Fatal("sudo was not detected")
	}
	if c.Class != Irrevocable {
		t.Fatalf("elevated directory creation classified %s, want IRREVOCABLE", c.Class)
	}
	inner := classOf(t, "mkdir", "a")
	if inner.Class != Compensable {
		t.Fatalf("unelevated directory creation classified %s, want COMPENSABLE", inner.Class)
	}
}

// Observe posture keeps its non-enforcing behavior for non-prohibited
// classifications, including commands the table cannot classify.
func TestObservePostureAdmitsUnclassifiedAsDocumented(t *testing.T) {
	d := Decide(classOf(t, "some-binary-nobody-has-heard-of", "--go"), Observe, Approvals{})
	if d.Outcome != Admitted {
		t.Fatal("observe posture refused an unclassified non-prohibited command")
	}
	if d.Reason == "" || d.Posture != Observe {
		t.Fatal("observe posture did not record itself in the decision")
	}
}

// The posture is part of the policy identity, so evidence cannot claim an
// enforcement that was not in force.
func TestPolicyHashSeparatesPostures(t *testing.T) {
	if Hash(Enforce, Approvals{}) == Hash(Observe, Approvals{}) {
		t.Fatal("enforce and observe share a policy_hash")
	}
	if Hash(Enforce, Approvals{}) == Hash(Enforce, Approvals{Irrevocable: true}) {
		t.Fatal("approvals do not change the policy_hash")
	}
}

func TestShellStringsAreNotGuessedAt(t *testing.T) {
	c := classOf(t, "bash", "-c", "rm -rf /tmp/x")
	if c.Class != Unclassified {
		t.Fatalf("a shell string was classified %s; UEG cannot parse one and must say so", c.Class)
	}
}
