//go:build !windows

package ledger

import (
	"os"
	"path/filepath"
)

func replaceRecoveryPath(tempPath, destinationPath string) error {
	if err := os.Rename(tempPath, destinationPath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(destinationPath))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func removeRecoveryPath(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
