//go:build windows

package keys

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func preparePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a private directory", path)
	}
	return restrictAndVerifyDACL(path, true)
}

func securePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular private-key file", path)
	}
	return restrictAndVerifyDACL(path, false)
}

func checkPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a private directory", path)
	}
	owner, system, err := privateSIDs()
	if err != nil {
		return err
	}
	return verifyRestrictedDACL(path, owner, system)
}

func checkPrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular private-key file", path)
	}
	owner, system, err := privateSIDs()
	if err != nil {
		return err
	}
	return verifyRestrictedDACL(path, owner, system)
}

func restrictAndVerifyDACL(path string, directory bool) error {
	owner, system, err := privateSIDs()
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{
		explicitFullControl(owner, windows.TRUSTEE_IS_USER, inheritance),
		explicitFullControl(system, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, inheritance),
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build private DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("set protected private DACL: %w", err)
	}
	return verifyRestrictedDACL(path, owner, system)
}

func privateSIDs() (*windows.SID, *windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve current user SID: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	return user.User.Sid, system, nil
}

func explicitFullControl(sid *windows.SID, trusteeType windows.TRUSTEE_TYPE, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func verifyRestrictedDACL(path string, owner, system *windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read private DACL: %w", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("read private DACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private DACL still inherits permissions")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read private DACL entries: %w", err)
	}
	if dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("private DACL has no access entries")
	}
	seenOwner := false
	seenSystem := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("read private DACL entry %d: %w", index, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("private DACL entry %d is not an allow entry", index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(owner):
			seenOwner = true
		case sid.Equals(system):
			seenSystem = true
		default:
			name, _, _, lookupErr := sid.LookupAccount("")
			if lookupErr != nil {
				name = sid.String()
			}
			return fmt.Errorf("private DACL grants access to unexpected principal %s", name)
		}
	}
	if !seenOwner || !seenSystem {
		return fmt.Errorf("private DACL does not grant both owner and LocalSystem access")
	}
	return nil
}
