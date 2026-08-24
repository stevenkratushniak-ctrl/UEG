//go:build windows

package keys

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestGeneratedPrivateKeyHasProtectedOwnerAndSystemOnlyDACL(t *testing.T) {
	home := t.TempDir()
	privatePath := filepath.Join(home, "keys", "ed25519_private.pem")
	publicPath := filepath.Join(home, "keys", "ed25519_public.pem")
	if _, err := LoadOrCreate(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	owner, system, err := privateSIDs()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRestrictedDACL(filepath.Dir(privatePath), owner, system); err != nil {
		t.Fatalf("key directory ACL: %v", err)
	}
	if err := verifyRestrictedDACL(privatePath, owner, system); err != nil {
		t.Fatalf("private key ACL: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(privatePath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl.AceCount == 0 {
		t.Fatal("private key DACL has no access entries")
	}
	if _, err := os.ReadFile(privatePath); err != nil {
		t.Fatalf("owner cannot read secured private key: %v", err)
	}
}

func TestProtectedRecoveryFilePreservesOwnerSelectedParentDACL(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "owner-selected")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "recovery.json")
	if err := WriteProtectedFile(path, []byte("synthetic encrypted recovery package")); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("protected recovery write changed parent DACL\nbefore=%s\nafter=%s", before.String(), after.String())
	}
	if err := CheckProtectedFile(path); err != nil {
		t.Fatalf("recovery package file DACL: %v", err)
	}
}
