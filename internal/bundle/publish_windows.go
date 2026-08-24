//go:build windows

package bundle

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func publishNoReplace(tempPath, outputPath string) (bool, error) {
	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return false, err
	}
	to, err := windows.UTF16PtrFromString(outputPath)
	if err != nil {
		return false, err
	}
	err = windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
		return false, fmt.Errorf("%w: %v", os.ErrExist, err)
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
