package activatecommand

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func macProtected(info os.FileInfo, directory, private bool, uid uint32) bool {
	if info == nil || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 {
		return false
	}
	mask := os.FileMode(0022)
	if private {
		mask = 0077
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uid && info.Mode().Perm()&mask == 0 && (directory || owner.Nlink == 1)
}

func openMacProtected(path string, directory, private bool, uid uint32) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !macProtected(before, directory, private, uid) {
		return nil, ErrAccess
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, ErrAccess
	}
	file := os.NewFile(uintptr(fd), path)
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !macProtected(after, directory, private, uid) {
		file.Close()
		return nil, ErrAccess
	}
	return file, nil
}

func readMacConfiguration(path string, uid uint32) ([]byte, error) {
	file, err := openMacProtected(path, false, true, uid)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() < 1 || info.Size() > maxConfiguration {
		return nil, ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfiguration+1))
	if err != nil || len(data) > maxConfiguration {
		return nil, ErrConfiguration
	}
	return data, nil
}

func ensureMacDirectory(path string, uid uint32) (*os.File, error) {
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrConfiguration
	}
	return openMacProtected(path, true, true, uid)
}

// Publish an entire marked INI through an exclusive hard link in the retained
// private parent. A competing winner is never overwritten or truncated.
func publishMacConfiguration(path string, data []byte, uid uint32) error {
	if len(data) == 0 || len(data) > maxConfiguration {
		return ErrConfiguration
	}
	parent, err := openMacProtected(filepath.Dir(path), true, true, uid)
	if err != nil {
		return err
	}
	defer parent.Close()
	temporary := ".activate-" + uuid.NewString() + ".tmp"
	fd, err := unix.Openat(int(parent.Fd()), temporary, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrConfiguration
	}
	file := os.NewFile(uintptr(fd), filepath.Join(filepath.Dir(path), temporary))
	owned, _ := file.Stat()
	defer func() {
		file.Close()
		var current unix.Stat_t
		if owned == nil {
			return
		}
		stat, ok := owned.Sys().(*syscall.Stat_t)
		if ok && unix.Fstatat(int(parent.Fd()), temporary, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && current.Dev == stat.Dev && current.Ino == stat.Ino {
			_ = unix.Unlinkat(int(parent.Fd()), temporary, 0)
		}
	}()
	if n, err := file.Write(data); err != nil || n != len(data) {
		return ErrConfiguration
	}
	if err := file.Sync(); err != nil {
		return ErrConfiguration
	}
	before, err := parent.Stat()
	current, currentErr := os.Lstat(filepath.Dir(path))
	if err != nil || currentErr != nil || !os.SameFile(before, current) || !macProtected(current, true, true, uid) {
		return ErrConfiguration
	}
	if err := unix.Linkat(int(parent.Fd()), temporary, int(parent.Fd()), filepath.Base(path), 0); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(parent.Fd()), temporary, 0); err != nil {
		return ErrConfiguration
	}
	if err := parent.Sync(); err != nil {
		return ErrConfiguration
	}
	return nil
}
