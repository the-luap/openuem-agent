package macsecurity

import (
	"errors"
	"os"
	"sync"
)

var (
	ErrRotationUnavailable = errors.New("FileVault rotation is unavailable")
	ErrRotationUnsupported = errors.New("FileVault rotation requires the root Mac agent")
	ErrRotationBusy        = errors.New("another FileVault rotation is active")
)

// RotationLease excludes other processes from the complete local rotation and
// crash-recovery lifecycle. Close releases the kernel lock, never the persistent
// lock file or protected journal. Process exit also releases the kernel lock.
type RotationLease struct {
	file     *os.File
	once     sync.Once
	closeErr error
}

func (l *RotationLease) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.file != nil {
			l.closeErr = l.file.Close()
		}
	})
	return l.closeErr
}
