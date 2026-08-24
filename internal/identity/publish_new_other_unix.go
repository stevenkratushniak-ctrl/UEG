//go:build !windows && !linux && !darwin

package identity

import (
	"fmt"
	"os"
)

func publishNewPath(sourcePath, destinationPath string) error {
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("identity: atomic no-replace directory publication is unsupported on this platform")
	}
	if err := os.Link(sourcePath, destinationPath); err != nil {
		return err
	}
	if err := os.Remove(sourcePath); err != nil {
		_ = os.Remove(destinationPath)
		return err
	}
	return syncParentDirectory(destinationPath)
}
