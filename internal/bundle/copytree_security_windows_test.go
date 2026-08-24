//go:build windows

package bundle

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// copyTreeSecurityMetadata preserves protected DACLs in the test clone. A
// byte-only Windows copy deliberately loses that protection and is correctly
// refused by the production key loader, so fork tests must retain the source
// security metadata instead of weakening the loader.
func copyTreeSecurityMetadata(source, destination string) error {
	return filepath.Walk(source, func(path string, _ os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("read source DACL for %s: %w", relative, err)
		}
		control, _, err := descriptor.Control()
		if err != nil {
			return fmt.Errorf("read source DACL control for %s: %w", relative, err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			return nil
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			return fmt.Errorf("read source DACL entries for %s: %w", relative, err)
		}
		if err := windows.SetNamedSecurityInfo(
			target,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil,
			nil,
			dacl,
			nil,
		); err != nil {
			return fmt.Errorf("preserve protected DACL for %s: %w", relative, err)
		}
		return nil
	})
}
