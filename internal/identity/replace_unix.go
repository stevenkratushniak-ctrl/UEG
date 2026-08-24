//go:build !windows

package identity

import (
	"os"
	"path/filepath"
)

func replacePath(tempPath, destinationPath string) error {
	if err := os.Rename(tempPath, destinationPath); err != nil {
		return err
	}
	return syncParentDirectory(destinationPath)
}

func syncParentDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
