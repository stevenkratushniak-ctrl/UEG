//go:build !windows

package keys

import (
	"fmt"
	"os"
)

func preparePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a private directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("directory permissions %04o permit group or other access", info.Mode().Perm())
	}
	return nil
}

func securePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular private-key file", path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	info, err = os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private-key permissions %04o permit group or other access", info.Mode().Perm())
	}
	return nil
}

func checkPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a private directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("directory permissions %04o permit group or other access", info.Mode().Perm())
	}
	return nil
}

func checkPrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular private-key file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private-key permissions %04o permit group or other access", info.Mode().Perm())
	}
	return nil
}
