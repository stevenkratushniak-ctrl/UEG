//go:build darwin

package identity

import "golang.org/x/sys/unix"

func publishNewPath(sourcePath, destinationPath string) error {
	if err := unix.RenamexNp(sourcePath, destinationPath, unix.RENAME_EXCL); err != nil {
		return err
	}
	return syncParentDirectory(destinationPath)
}
