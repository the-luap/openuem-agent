package localready

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/unix"
)

const (
	lockName      = ".openuem-readiness.lock"
	addressName   = ".openuem-readiness.address"
	addressPrefix = "openuem-readiness-v1:"
)

type linuxReadyDirectory struct {
	path  string
	parts []string
	files []*os.File
}

func openLinuxReadyDirectory(path string) (*linuxReadyDirectory, error) {
	if os.Geteuid() != 0 || !nativepath.Valid(path) || path == "/" {
		return nil, ErrUnavailable
	}
	d := &linuxReadyDirectory{path: path, parts: strings.Split(strings.TrimPrefix(path, "/"), "/")}
	accepted := false
	defer func() {
		if !accepted {
			d.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	d.files = append(d.files, os.NewFile(uintptr(fd), "/"))
	for _, part := range d.parts {
		parent := d.files[len(d.files)-1]
		if !linuxReadyProtectedDirectory(parent, false) {
			return nil, ErrUnavailable
		}
		fd, err = unix.Openat(int(parent.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, ErrUnavailable
		}
		d.files = append(d.files, os.NewFile(uintptr(fd), part))
	}
	if !d.valid() {
		return nil, ErrUnavailable
	}
	accepted = true
	return d, nil
}

func linuxReadyProtectedDirectory(file *os.File, private bool) bool {
	var st unix.Stat_t
	return unix.Fstat(int(file.Fd()), &st) == nil && st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07022 == 0 && (!private || st.Mode&07777 == 0700)
}

func (d *linuxReadyDirectory) valid() bool {
	if d == nil || len(d.files) != len(d.parts)+1 {
		return false
	}
	var actual, held unix.Stat_t
	if unix.Lstat("/", &actual) != nil || unix.Fstat(int(d.files[0].Fd()), &held) != nil || actual.Dev != held.Dev || actual.Ino != held.Ino {
		return false
	}
	for i, file := range d.files {
		if !linuxReadyProtectedDirectory(file, i == len(d.files)-1) {
			return false
		}
		if i > 0 && (unix.Fstatat(int(d.files[i-1].Fd()), d.parts[i-1], &actual, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(int(file.Fd()), &held) != nil || actual.Dev != held.Dev || actual.Ino != held.Ino || actual.Mode&unix.S_IFMT != unix.S_IFDIR) {
			return false
		}
	}
	return true
}

func (d *linuxReadyDirectory) root() *os.File { return d.files[len(d.files)-1] }
func (d *linuxReadyDirectory) close() error {
	var result error
	for i := len(d.files) - 1; i >= 0; i-- {
		if err := d.files[i].Close(); result == nil {
			result = err
		}
	}
	d.files = nil
	return result
}

func linuxReadyPrivate(st unix.Stat_t) bool {
	return st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Nlink == 1
}

func sameLinuxReadyStamp(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func (d *linuxReadyDirectory) entry(name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	if filepath.Base(name) != name || name == "." || name == ".." || !d.valid() {
		return st, ErrConflict
	}
	err := unix.Fstatat(int(d.root().Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	return st, err
}

func (d *linuxReadyDirectory) matches(name string, file *os.File) bool {
	entry, err := d.entry(name)
	var held unix.Stat_t
	return err == nil && unix.Fstat(int(file.Fd()), &held) == nil && sameLinuxReadyStamp(entry, held) && linuxReadyPrivate(held)
}

func (d *linuxReadyDirectory) openLock() (*os.File, error) {
	if !d.valid() {
		return nil, ErrUnavailable
	}
	fd, err := unix.Openat(int(d.root().Fd()), lockName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(int(d.root().Fd()), lockName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), lockName)
	var held unix.Stat_t
	if !d.matches(lockName, file) || unix.Fstat(fd, &held) != nil || held.Size != 0 {
		file.Close()
		return nil, ErrConflict
	}
	return file, nil
}

func (d *linuxReadyDirectory) address(create bool) (string, error) {
	if _, err := d.entry(addressName); errors.Is(err, unix.ENOENT) && create {
		data := []byte(addressPrefix + uuid.NewString() + "\n")
		temporary := ".ready-address-" + uuid.NewString() + ".tmp"
		fd, err := unix.Openat(int(d.root().Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return "", ErrUnavailable
		}
		file := os.NewFile(uintptr(fd), temporary)
		defer file.Close()
		defer func() {
			if d.matches(temporary, file) {
				_ = unix.Unlinkat(int(d.root().Fd()), temporary, 0)
			}
		}()
		if n, err := file.Write(data); err != nil || n != len(data) || file.Sync() != nil || !d.matches(temporary, file) {
			return "", ErrUnavailable
		}
		if err := unix.Renameat2(int(d.root().Fd()), temporary, int(d.root().Fd()), addressName, unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, unix.EEXIST) {
			return "", ErrUnavailable
		}
		if d.root().Sync() != nil {
			return "", ErrUnavailable
		}
	}
	if !d.valid() {
		return "", ErrUnavailable
	}
	fd, err := unix.Openat(int(d.root().Fd()), addressName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), addressName)
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !linuxReadyPrivate(before) || before.Size != int64(len(addressPrefix)+37) || !d.matches(addressName, file) {
		return "", ErrConflict
	}
	data, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil || unix.Fstat(fd, &after) != nil || !sameLinuxReadyStamp(before, after) || !d.matches(addressName, file) || len(data) != int(before.Size) || !strings.HasPrefix(string(data), addressPrefix) || !strings.HasSuffix(string(data), "\n") {
		return "", ErrConflict
	}
	id := strings.TrimSuffix(strings.TrimPrefix(string(data), addressPrefix), "\n")
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id || parsed.Version() != 4 {
		return "", ErrConflict
	}
	return ".ready-" + id + ".sock", nil
}

func linuxReadySocket(st unix.Stat_t) bool {
	return st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFSOCK && st.Mode&07777 == 0600 && st.Nlink == 1
}

func (d *linuxReadyDirectory) removeSocket(name string, expected unix.Stat_t) error {
	current, err := d.entry(name)
	if err != nil || !linuxReadySocket(current) || current.Dev != expected.Dev || current.Ino != expected.Ino {
		return ErrConflict
	}
	if unix.Unlinkat(int(d.root().Fd()), name, 0) != nil {
		return ErrUnavailable
	}
	return nil
}
