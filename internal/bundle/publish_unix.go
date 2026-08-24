//go:build !windows

package bundle

import (
	"os"
	"path/filepath"
)

func publishNoReplace(tempPath, outputPath string) (bool, error) {
	if err := os.Link(tempPath, outputPath); err != nil {
		return false, err
	}
	published := true
	if err := syncDirectory(filepath.Dir(outputPath)); err != nil {
		return published, err
	}
	if err := os.Remove(tempPath); err != nil {
		return published, err
	}
	if err := syncDirectory(filepath.Dir(outputPath)); err != nil {
		return published, err
	}
	return published, nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
