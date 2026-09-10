package enrollmentstore

import (
	"errors"
	"os"
	"sync"
)

var ErrServiceBusy = errors.New("the individual installation already has an active service owner")

const serviceLeaseName = ".openuem-service.lock"

// ServiceLease excludes other service processes from one protected installation.
// Keep it through startup recovery, all credential users, joined shutdown and
// renewal/reconstruction. It is independent of the FileVault execution lease and
// never proves that an orphaned OS mutation stopped. Kernel ownership ends on
// Close or process exit; the empty lock file is permanent and never unlinked.
type ServiceLease struct {
	mu         sync.RWMutex
	directory  string
	file, root *os.File
	owner      uint32
}

func (l *ServiceLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	if l.file != nil {
		err = l.file.Close()
		l.file = nil
	}
	if l.root != nil {
		if closeErr := l.root.Close(); err == nil {
			err = closeErr
		}
		l.root = nil
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

// Validate checks that the held descriptors still name the same private native
// directory and lock file. It neither repairs access controls nor opens another
// identity. The caller must choose administrator-controlled parent directories,
// as with OpenNative; a lease cannot secure an attacker-writable ancestor.
func (l *ServiceLease) Validate() error {
	if l == nil {
		return ErrUnavailable
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.file == nil || l.root == nil {
		return ErrUnavailable
	}
	return l.validateNative()
}

// ValidateDirectory also binds a borrowed lease to the requested installation.
func (l *ServiceLease) ValidateDirectory(directory string) error {
	if l == nil {
		return ErrUnavailable
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.file == nil || l.root == nil || l.directory != directory {
		return ErrUnavailable
	}
	return l.validateNative()
}
