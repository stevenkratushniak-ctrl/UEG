//go:build linux

package identity

import "golang.org/x/sys/unix"

func publishNewPath(sourcePath, destinationPath string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, sourcePath, unix.AT_FDCWD, destinationPath, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncParentDirectory(destinationPath)
}
