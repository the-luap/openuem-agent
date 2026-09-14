package linuxservice

import (
	"context"
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const wantsDirectory = "multi-user.target.wants"

// unitEnablement observes only the persistent, canonical enablement link. It
// never follows, creates, replaces or removes a link, including during Close.
// The controller must separately retain the target unit file and manager state.
type unitEnablement struct {
	mu        sync.Mutex
	parent    *protectedDirectory
	directory *os.File
	link      *os.File
	stamp     unix.Stat_t
	closed    bool
}

func openUnitEnablement() (*unitEnablement, error) {
	return openUnitEnablementAt("/etc/systemd/system")
}

// Only owned native fixtures may supply an alternate parent. Both the link name
// and its literal absolute target remain fixed.
func openUnitEnablementAt(parent string) (*unitEnablement, error) {
	d, err := openProtectedDirectory(parent)
	if err != nil {
		return nil, ErrUnit
	}
	e := &unitEnablement{parent: d}
	if _, err := e.inspect(); err != nil {
		e.Close()
		return nil, err
	}
	return e, nil
}

func (e *unitEnablement) validDirectory() bool {
	if !e.parent.valid() || e.directory == nil || !protectedDirectoryFile(e.directory) {
		return false
	}
	var current, held unix.Stat_t
	return unix.Fstatat(int(e.parent.root().Fd()), wantsDirectory, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && unix.Fstat(int(e.directory.Fd()), &held) == nil && current.Dev == held.Dev && current.Ino == held.Ino && current.Mode&unix.S_IFMT == unix.S_IFDIR
}

func (e *unitEnablement) matchesLink(file *os.File, stamp unix.Stat_t) bool {
	if !e.validDirectory() || stamp.Uid != 0 || stamp.Mode&unix.S_IFMT != unix.S_IFLNK || stamp.Mode&07000 != 0 || stamp.Nlink != 1 || stamp.Size != int64(len(UnitPath)) {
		return false
	}
	var current, held unix.Stat_t
	return unix.Fstatat(int(e.directory.Fd()), UnitName, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && unix.Fstat(int(file.Fd()), &held) == nil && sameStamp(current, stamp) && sameStamp(held, stamp)
}

func (e *unitEnablement) readLink(file *os.File, stamp unix.Stat_t) bool {
	if !e.matchesLink(file, stamp) {
		return false
	}
	// Linux readlinkat with an empty path reads this held O_PATH symlink itself.
	// An extra byte detects a longer target; no allocation depends on peer data.
	var data [len(UnitPath) + 1]byte
	n, err := unix.Readlinkat(int(file.Fd()), "", data[:])
	return err == nil && n == len(UnitPath) && string(data[:n]) == UnitPath && e.matchesLink(file, stamp)
}

func (e *unitEnablement) inspectLocked() (bool, error) {
	if e.closed || !e.parent.valid() {
		return false, ErrUnit
	}
	if e.directory == nil {
		fd, err := unix.Openat(int(e.parent.root().Fd()), wantsDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && e.parent.valid() {
			return false, nil
		}
		if err != nil {
			return false, ErrUnit
		}
		e.directory = os.NewFile(uintptr(fd), wantsDirectory)
	}
	if !e.validDirectory() {
		return false, ErrUnit
	}
	if e.link != nil {
		if !e.readLink(e.link, e.stamp) {
			return false, ErrUnit
		}
		return true, nil
	}
	fd, err := unix.Openat(int(e.directory.Fd()), UnitName, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) && e.validDirectory() {
		return false, nil
	}
	if err != nil {
		return false, ErrUnit
	}
	file := os.NewFile(uintptr(fd), UnitName)
	var stamp unix.Stat_t
	if unix.Fstat(fd, &stamp) != nil || !e.readLink(file, stamp) {
		file.Close()
		return false, ErrUnit
	}
	e.link, e.stamp = file, stamp
	return true, nil
}

func (e *unitEnablement) inspect() (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.inspectLocked()
}

// flush makes the admitted namespace durable even when the manager created the
// link in another process. It cannot create a missing link or repair a conflict.
func (e *unitEnablement) flush(ctx context.Context) error {
	if ctx == nil {
		return ErrUnit
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if present, err := e.inspectLocked(); err != nil || !present {
		return ErrUnit
	}
	if e.directory.Sync() != nil || e.parent.root().Sync() != nil {
		return ErrUnit
	}
	if present, err := e.inspectLocked(); err != nil || !present {
		return ErrUnit
	}
	return ctx.Err()
}

func (e *unitEnablement) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed {
		e.closed = true
		if e.link != nil {
			e.link.Close()
		}
		if e.directory != nil {
			e.directory.Close()
		}
		e.parent.close()
	}
	return nil
}
