package enrollcommand

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/unix"
)

// Linux bootstrap inputs are copied only through retained, root-owned ancestors.
// A privileged command must not accept a private file under a writable parent.
type linuxInputDirectory struct {
	parts []string
	files []*os.File
}

func openLinuxInputDirectory(path string, create bool) (*linuxInputDirectory, error) {
	if os.Geteuid() != 0 || !nativepath.Valid(path) || path == "/" {
		return nil, ErrOptions
	}
	d := &linuxInputDirectory{parts: strings.Split(strings.TrimPrefix(path, "/"), "/")}
	accepted := false
	defer func() {
		if !accepted {
			d.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrOptions
	}
	d.files = append(d.files, os.NewFile(uintptr(fd), "/"))
	for i, part := range d.parts {
		parent := d.files[len(d.files)-1]
		if !linuxInputDirectorySafe(parent, false) {
			return nil, ErrOptions
		}
		fd, err = unix.Openat(int(parent.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(err, unix.ENOENT) && create && i == len(d.parts)-1 {
			// Only the final private staging directory may be created. No parent
			// permissions are repaired, and existing entries are never replaced.
			if err = unix.Mkdirat(int(parent.Fd()), part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				return nil, ErrOptions
			}
			if parent.Sync() != nil {
				return nil, ErrOptions
			}
			fd, err = unix.Openat(int(parent.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if err != nil {
			return nil, ErrOptions
		}
		d.files = append(d.files, os.NewFile(uintptr(fd), part))
	}
	if !d.valid(create) {
		return nil, ErrOptions
	}
	accepted = true
	return d, nil
}

func linuxInputDirectorySafe(file *os.File, private bool) bool {
	var st unix.Stat_t
	return unix.Fstat(int(file.Fd()), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == 0 && st.Mode&07022 == 0 && (!private || st.Mode&07777 == 0700)
}

func (d *linuxInputDirectory) valid(private bool) bool {
	var actual, pinned unix.Stat_t
	if len(d.files) != len(d.parts)+1 || unix.Lstat("/", &actual) != nil || unix.Fstat(int(d.files[0].Fd()), &pinned) != nil || actual.Dev != pinned.Dev || actual.Ino != pinned.Ino {
		return false
	}
	for i, file := range d.files {
		if !linuxInputDirectorySafe(file, private && i == len(d.files)-1) {
			return false
		}
		if i > 0 && (unix.Fstatat(int(d.files[i-1].Fd()), d.parts[i-1], &actual, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(int(file.Fd()), &pinned) != nil || actual.Dev != pinned.Dev || actual.Ino != pinned.Ino || actual.Mode&unix.S_IFMT != unix.S_IFDIR) {
			return false
		}
	}
	return true
}

func (d *linuxInputDirectory) close() error {
	var result error
	for i := len(d.files) - 1; i >= 0; i-- {
		if err := d.files[i].Close(); result == nil {
			result = err
		}
	}
	d.files = nil
	return result
}

func prepareNativeStaging(path string) error {
	directory, err := openLinuxInputDirectory(path, true)
	if err != nil {
		return ErrPackage
	}
	return directory.close()
}

func readNativeInput(path string, limit int64) ([]byte, error) {
	if !nativepath.Valid(path) || path == "/" || limit <= 0 || limit > 8192 {
		return nil, ErrOptions
	}
	directory, err := openLinuxInputDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, ErrOptions
	}
	defer directory.close()
	parent := directory.files[len(directory.files)-1]
	name := filepath.Base(path)
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrOptions
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before, after, entry unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || before.Uid != 0 || before.Nlink != 1 || before.Size < 1 || before.Size > limit {
		return nil, ErrOptions
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != before.Size || !directory.valid(false) || unix.Fstat(fd, &after) != nil || unix.Fstatat(int(parent.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameLinuxInput(before, after) || !sameLinuxInput(before, entry) {
		clear(data)
		return nil, ErrOptions
	}
	return data, nil
}

func sameLinuxInput(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
