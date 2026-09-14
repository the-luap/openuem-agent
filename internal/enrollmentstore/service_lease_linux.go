package enrollmentstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/unix"
)

// AcquireServiceLease admits one root service for an existing private installation.
// Every ancestor must be root-owned and non-writable by other users. In particular,
// a sticky shared directory does not authorize an installation beneath it.
func AcquireServiceLease(directory string) (*ServiceLease, error) {
	if os.Geteuid() != 0 || !nativepath.Valid(directory) || directory == "/" {
		return nil, ErrUnavailable
	}
	l := &ServiceLease{directory: directory, owner: 0}
	accepted := false
	defer func() {
		if !accepted {
			l.Close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	current := os.NewFile(uintptr(fd), "/")
	l.parents = append(l.parents, current)
	if !linuxLeaseDirectory(current, false) {
		return nil, ErrUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(directory, "/"), "/")
	for i, part := range parts {
		fd, err = unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, ErrUnavailable
		}
		current = os.NewFile(uintptr(fd), part)
		last := i == len(parts)-1
		if last {
			l.root = current
		} else {
			l.parents = append(l.parents, current)
		}
		if !linuxLeaseDirectory(current, last) {
			return nil, ErrUnavailable
		}
	}
	lock, err := unix.Openat(int(l.root.Fd()), serviceLeaseName, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	l.file = os.NewFile(uintptr(lock), filepath.Join(directory, serviceLeaseName))
	if l.validateNative() != nil {
		return nil, ErrUnavailable
	}
	if err = unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrServiceBusy
		}
		return nil, ErrUnavailable
	}
	// Publish the permanent empty lock before exposing service ownership. Failure
	// preserves the file and releases the kernel lease, without repairing state.
	if l.file.Sync() != nil || l.root.Sync() != nil || l.validateNative() != nil {
		return nil, ErrUnavailable
	}
	accepted = true
	return l, nil
}

func linuxLeaseDirectory(file *os.File, private bool) bool {
	var stat unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&07022 != 0 {
		return false
	}
	return !private || stat.Mode&0777 == 0700
}

func linuxLeaseSame(parent *os.File, name string, held *os.File) bool {
	var current, pinned unix.Stat_t
	return parent != nil && held != nil &&
		unix.Fstatat(int(parent.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		unix.Fstat(int(held.Fd()), &pinned) == nil &&
		current.Mode&unix.S_IFMT == pinned.Mode&unix.S_IFMT && current.Dev == pinned.Dev && current.Ino == pinned.Ino
}

func (l *ServiceLease) validateNative() error {
	parts := strings.Split(strings.TrimPrefix(l.directory, "/"), "/")
	if len(l.parents) != len(parts) || !linuxLeaseDirectory(l.root, true) || l.file == nil {
		return ErrUnavailable
	}
	var root unix.Stat_t
	if unix.Lstat("/", &root) != nil {
		return ErrUnavailable
	}
	for i, parent := range l.parents {
		if !linuxLeaseDirectory(parent, false) {
			return ErrUnavailable
		}
		if i == 0 {
			var pinned unix.Stat_t
			if unix.Fstat(int(parent.Fd()), &pinned) != nil || root.Dev != pinned.Dev || root.Ino != pinned.Ino {
				return ErrUnavailable
			}
		}
		next := l.root
		if i+1 < len(l.parents) {
			next = l.parents[i+1]
		}
		if !linuxLeaseSame(parent, parts[i], next) {
			return ErrUnavailable
		}
	}
	var file unix.Stat_t
	if unix.Fstat(int(l.file.Fd()), &file) != nil || file.Mode&unix.S_IFMT != unix.S_IFREG || file.Uid != 0 || file.Mode&07777 != 0600 || file.Nlink != 1 || file.Size != 0 || !linuxLeaseSame(l.root, serviceLeaseName, l.file) {
		return ErrUnavailable
	}
	return nil
}
