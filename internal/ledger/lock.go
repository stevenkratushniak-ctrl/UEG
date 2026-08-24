package ledger

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/stevenkratushniak-ctrl/ueg/internal/filelock"
)

const lockWait = 30 * time.Second

// HomeLock serializes UEG operations that share one evidence home. The lock
// is owned by the operating system and is released if the process exits.
type HomeLock struct {
	lock *filelock.Lock
}

// AcquireHomeLock obtains the evidence-home lock. When create is false, a
// missing home or lock is reported without creating anything.
func AcquireHomeLock(home string, create bool) (*HomeLock, error) {
	if create {
		if err := os.MkdirAll(home, 0o700); err != nil {
			return nil, fmt.Errorf("ledger: create evidence directory: %w", err)
		}
	} else {
		info, err := os.Stat(home)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("ledger: evidence home is not a directory: %s", home)
		}
	}

	path := filepath.Join(home, ".ueg.lock")
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	lock, err := filelock.Acquire(path, flags, 0o600, lockWait)
	if err != nil {
		if !create && os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ledger: evidence directory is busy: %w", err)
	}
	return &HomeLock{lock: lock}, nil
}

// Release relinquishes the home lock.
func (l *HomeLock) Release() error {
	if l == nil || l.lock == nil {
		return nil
	}
	err := l.lock.Release()
	l.lock = nil
	return err
}
