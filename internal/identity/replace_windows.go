//go:build windows

package identity

import "golang.org/x/sys/windows"

func replacePath(tempPath, destinationPath string) error {
	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destinationPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func publishNewPath(sourcePath, destinationPath string) error {
	from, err := windows.UTF16PtrFromString(sourcePath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destinationPath)
	if err != nil {
		return err
	}
	// Omitting MOVEFILE_REPLACE_EXISTING makes the kernel, rather than a
	// check-then-rename race, enforce the no-overwrite contract.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
