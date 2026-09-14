package linuxservice

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// protectedDirectory retains every component, including '/', without following
// links. Callers keep it alive until all operations using its descriptors end.
type protectedDirectory struct {
	parts []string
	files []*os.File
}

func openProtectedDirectory(path string) (_ *protectedDirectory, resultErr error) {
	if os.Geteuid() != 0 || (path != "/" && !validPath(path)) {
		return nil, ErrManager
	}
	d := &protectedDirectory{}
	if path != "/" {
		d.parts = strings.Split(strings.TrimPrefix(path, "/"), "/")
	}
	defer func() {
		if resultErr != nil {
			d.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrManager
	}
	d.files = append(d.files, os.NewFile(uintptr(fd), "/"))
	for _, part := range d.parts {
		if !protectedDirectoryFile(d.root()) {
			return nil, ErrManager
		}
		fd, err = unix.Openat(int(d.root().Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, ErrManager
		}
		d.files = append(d.files, os.NewFile(uintptr(fd), part))
	}
	if !d.valid() {
		return nil, ErrManager
	}
	return d, nil
}

func protectedDirectoryFile(file *os.File) bool {
	var st unix.Stat_t
	return unix.Fstat(int(file.Fd()), &st) == nil && st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07022 == 0
}

func (d *protectedDirectory) valid() bool {
	if d == nil || len(d.files) != len(d.parts)+1 {
		return false
	}
	var actual, held unix.Stat_t
	if unix.Lstat("/", &actual) != nil || unix.Fstat(int(d.files[0].Fd()), &held) != nil || actual.Dev != held.Dev || actual.Ino != held.Ino {
		return false
	}
	for i, file := range d.files {
		if !protectedDirectoryFile(file) {
			return false
		}
		if i > 0 && (unix.Fstatat(int(d.files[i-1].Fd()), d.parts[i-1], &actual, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(int(file.Fd()), &held) != nil || actual.Dev != held.Dev || actual.Ino != held.Ino || actual.Mode&unix.S_IFMT != unix.S_IFDIR) {
			return false
		}
	}
	return true
}

func (d *protectedDirectory) root() *os.File { return d.files[len(d.files)-1] }

func (d *protectedDirectory) close() {
	for i := len(d.files) - 1; i >= 0; i-- {
		_ = d.files[i].Close()
	}
	d.files = nil
}

func sameStamp(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
