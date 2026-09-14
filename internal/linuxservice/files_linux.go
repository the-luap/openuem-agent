package linuxservice

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// unitFile owns only the canonical definition. It cannot enable or start a
// service; the controller must separately admit the effective manager state.
type unitFile struct {
	mu        sync.Mutex
	directory *protectedDirectory
	file      *os.File
	stamp     unix.Stat_t
	spec      Spec
	closed    bool
}

func openUnitFile(spec Spec) (*unitFile, error) {
	return openUnitFileAt(UnitPath, spec)
}

// The alternate path is private to owned native fixtures. The basename remains
// fixed even there; no caller-selected service name is part of the contract.
func openUnitFileAt(filename string, spec Spec) (*unitFile, error) {
	if !spec.Valid() || !validPath(filename) || path.Base(filename) != UnitName {
		return nil, ErrUnit
	}
	d, err := openProtectedDirectory(path.Dir(filename))
	if err != nil {
		return nil, ErrUnit
	}
	u := &unitFile{directory: d, spec: spec}
	if _, err := u.inspect(); err != nil {
		u.Close()
		return nil, err
	}
	return u, nil
}

func unitMetadata(st unix.Stat_t) bool {
	mode := st.Mode & 07777
	return st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && (mode == 0600 || mode == 0644) && st.Size > 0 && st.Size <= MaxUnitSize
}

func (u *unitFile) matchesEntry(name string, file *os.File, stamp unix.Stat_t) bool {
	var current, held unix.Stat_t
	return u.directory.valid() && unix.Fstatat(int(u.directory.root().Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && unix.Fstat(int(file.Fd()), &held) == nil && sameStamp(current, stamp) && sameStamp(held, stamp) && held.Uid == 0 && held.Nlink == 1 && held.Mode&unix.S_IFMT == unix.S_IFREG && (held.Mode&07777 == 0600 || held.Mode&07777 == 0644) && held.Size >= 0 && held.Size <= MaxUnitSize
}

func (u *unitFile) read(file *os.File, stamp unix.Stat_t) bool {
	if !unitMetadata(stamp) || !u.matchesEntry(UnitName, file, stamp) {
		return false
	}
	data := make([]byte, stamp.Size+1)
	n, err := file.ReadAt(data, 0)
	return errors.Is(err, io.EOF) && int64(n) == stamp.Size && Matches(data[:n], u.spec) && u.matchesEntry(UnitName, file, stamp)
}

// inspectLocked may acquire an exact existing unit on the first observation.
// Once acquired, even a byte-identical inode replacement fails for this owner.
func (u *unitFile) inspectLocked() (bool, error) {
	if u.closed || !u.directory.valid() {
		return false, ErrUnit
	}
	if u.file != nil {
		if !u.read(u.file, u.stamp) {
			return false, ErrUnit
		}
		return true, nil
	}
	fd, err := unix.Openat(int(u.directory.root().Fd()), UnitName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		if !u.directory.valid() {
			return false, ErrUnit
		}
		return false, nil
	}
	if err != nil {
		return false, ErrUnit
	}
	file := os.NewFile(uintptr(fd), UnitName)
	var stamp unix.Stat_t
	if unix.Fstat(fd, &stamp) != nil || !unitMetadata(stamp) || !u.read(file, stamp) {
		file.Close()
		return false, ErrUnit
	}
	u.file, u.stamp = file, stamp
	return true, nil
}

func (u *unitFile) inspect() (bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.inspectLocked()
}

// publish creates and flushes a complete definition, then publishes it with
// renameat2(NOREPLACE). Existing definitions are never overwritten. Exact
// concurrent publication is admitted through the normal protected read path.
func (u *unitFile) publish(ctx context.Context) error {
	if ctx == nil {
		return ErrUnit
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if present, err := u.inspectLocked(); err != nil {
		return err
	} else if present {
		return ctx.Err()
	}
	data, err := Render(u.spec)
	if err != nil {
		return err
	}
	name := ".openuem-unit-" + uuid.NewString() + ".tmp"
	fd, err := unix.Openat(int(u.directory.root().Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrUnit
	}
	file := os.NewFile(uintptr(fd), name)
	retained := false
	defer func() {
		if !retained {
			// Remove only this original temporary inode under unchanged protected
			// ancestry. Never clean an unknown replacement or the installed unit.
			var held unix.Stat_t
			if unix.Fstat(fd, &held) == nil && u.matchesEntry(name, file, held) {
				_ = unix.Unlinkat(int(u.directory.root().Fd()), name, 0)
			}
			file.Close()
		}
	}()
	if n, err := file.Write(data); err != nil || n != len(data) {
		return ErrUnit
	}
	if unix.Fchmod(fd, 0644) != nil || file.Sync() != nil {
		return ErrUnit
	}
	var stamp unix.Stat_t
	if unix.Fstat(fd, &stamp) != nil || !u.matchesEntry(name, file, stamp) {
		return ErrUnit
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err = unix.Renameat2(int(u.directory.root().Fd()), name, int(u.directory.root().Fd()), UnitName, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EEXIST) {
		present, inspectErr := u.inspectLocked()
		if inspectErr != nil || !present {
			return ErrUnit
		}
		// An exact winner may not yet have flushed its parent. Make our own
		// successful observation durable before reporting publication complete.
		if u.directory.root().Sync() != nil {
			return ErrUnit
		}
		if _, err := u.inspectLocked(); err != nil {
			return err
		}
		return ctx.Err()
	}
	if err != nil {
		return ErrUnit
	}
	u.file = file
	retained = true
	if unix.Fstat(fd, &u.stamp) != nil || u.directory.root().Sync() != nil {
		return ErrUnit
	}
	if _, err := u.inspectLocked(); err != nil {
		return err
	}
	return ctx.Err()
}

// Close releases descriptors only. An installed definition survives cancellation
// or an uncertain later registration outcome and is validated on a retry.
func (u *unitFile) Close() error {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.closed {
		u.closed = true
		if u.file != nil {
			u.file.Close()
		}
		u.directory.close()
	}
	return nil
}
