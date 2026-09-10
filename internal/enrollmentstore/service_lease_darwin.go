package enrollmentstore

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/unix"
)

// AcquireServiceLease requires an existing root-owned private installation.
// It never creates a directory, follows the final symlink or repairs permissions.
func AcquireServiceLease(directory string) (*ServiceLease, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnavailable
	}
	return acquireServiceLease(directory, 0)
}

func acquireServiceLease(directory string, owner uint32) (*ServiceLease, error) {
	if !nativepath.Valid(directory) || uint32(os.Geteuid()) != owner {
		return nil, ErrUnavailable
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	l := &ServiceLease{directory: directory, root: os.NewFile(uintptr(fd), directory), owner: owner}
	accepted := false
	defer func() {
		if !accepted {
			l.Close()
		}
	}()
	var root unix.Stat_t
	if unix.Fstat(fd, &root) != nil || root.Mode&unix.S_IFMT != unix.S_IFDIR || root.Uid != owner || root.Mode&0777 != 0700 {
		return nil, ErrUnavailable
	}
	lock, err := unix.Openat(fd, serviceLeaseName, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	l.file = os.NewFile(uintptr(lock), filepath.Join(directory, serviceLeaseName))
	if l.validateNative() != nil {
		return nil, ErrUnavailable
	}
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrServiceBusy
		}
		return nil, ErrUnavailable
	}
	if l.validateNative() != nil {
		return nil, ErrUnavailable
	}
	accepted = true
	return l, nil
}

func (l *ServiceLease) validateNative() error {
	var root, file, currentRoot, currentFile unix.Stat_t
	if unix.Fstat(int(l.root.Fd()), &root) != nil || unix.Fstat(int(l.file.Fd()), &file) != nil || unix.Lstat(l.directory, &currentRoot) != nil || unix.Fstatat(int(l.root.Fd()), serviceLeaseName, &currentFile, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrUnavailable
	}
	if root.Mode&unix.S_IFMT != unix.S_IFDIR || root.Uid != l.owner || root.Mode&0777 != 0700 || file.Mode&unix.S_IFMT != unix.S_IFREG || file.Uid != l.owner || file.Mode&0777 != 0600 || file.Nlink != 1 || file.Size != 0 || currentRoot.Mode&unix.S_IFMT != unix.S_IFDIR || currentRoot.Dev != root.Dev || currentRoot.Ino != root.Ino || currentFile.Mode&unix.S_IFMT != unix.S_IFREG || currentFile.Dev != file.Dev || currentFile.Ino != file.Ino {
		return ErrUnavailable
	}
	return nil
}
