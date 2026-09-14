package packagesignature

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/unix"
)

// Every object retains its complete root-owned namespace. Public publisher keys
// may be readable by others; neither they nor any ancestor may be writable by
// another principal. Root remains inside the native package trust boundary.
type linuxSignatureFile struct {
	parts   []string
	parents []*os.File
	file    *os.File
	stamp   unix.Stat_t
	digest  [sha256.Size]byte
	names   []string
}

func openLinuxSignatureFile(path string, limit int64, directory, executable, private bool) (*linuxSignatureFile, error) {
	if os.Geteuid() != 0 || !nativepath.Valid(path) || path == "/" {
		return nil, ErrUntrusted
	}
	f := &linuxSignatureFile{parts: strings.Split(strings.TrimPrefix(path, "/"), "/")}
	accepted := false
	defer func() {
		if !accepted {
			f.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUntrusted
	}
	parent := os.NewFile(uintptr(fd), "/")
	f.parents = append(f.parents, parent)
	for i, part := range f.parts {
		if !linuxSignatureDirectory(parent) {
			return nil, ErrUntrusted
		}
		if private && i == len(f.parts)-1 {
			var st unix.Stat_t
			if unix.Fstat(int(parent.Fd()), &st) != nil || st.Mode&07777 != 0700 {
				return nil, ErrUntrusted
			}
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(f.parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		fd, err = unix.Openat(int(parent.Fd()), part, flags, 0)
		if err != nil {
			return nil, ErrUntrusted
		}
		opened := os.NewFile(uintptr(fd), part)
		if i == len(f.parts)-1 {
			f.file = opened
		} else {
			f.parents = append(f.parents, opened)
			parent = opened
		}
	}
	if unix.Fstat(int(f.file.Fd()), &f.stamp) != nil || f.stamp.Uid != 0 || f.stamp.Mode&07022 != 0 {
		return nil, ErrUntrusted
	}
	if directory {
		if !linuxSignatureDirectory(f.file) {
			return nil, ErrUntrusted
		}
		f.names, err = linuxSignatureNames(f.file)
	} else {
		if f.stamp.Mode&unix.S_IFMT != unix.S_IFREG || f.stamp.Nlink != 1 || f.stamp.Size < 1 || f.stamp.Size > limit || private && f.stamp.Mode&07777 != 0600 {
			return nil, ErrUntrusted
		}
		if executable {
			var magic [4]byte
			if f.stamp.Mode&0100 == 0 {
				return nil, ErrUntrusted
			}
			if _, err = f.file.ReadAt(magic[:], 0); err != nil || string(magic[:]) != "\x7fELF" {
				return nil, ErrUntrusted
			}
		}
		f.digest, err = linuxSignatureDigest(f.file, f.stamp.Size)
	}
	if err != nil || !f.valid() {
		return nil, ErrUntrusted
	}
	accepted = true
	return f, nil
}

func linuxSignatureDirectory(file *os.File) bool {
	var st unix.Stat_t
	return unix.Fstat(int(file.Fd()), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == 0 && st.Mode&07022 == 0
}

func linuxSignatureNames(file *os.File) ([]string, error) {
	// A new open description avoids sharing/reusing a directory seek position.
	fd, err := unix.Openat(int(file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUntrusted
	}
	reader := os.NewFile(uintptr(fd), "publisher directory")
	defer reader.Close()
	names, err := reader.Readdirnames(9)
	if len(names) > 8 || err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrUntrusted
	}
	slices.Sort(names)
	return names, nil
}

func (f *linuxSignatureFile) valid() bool {
	if f == nil || f.file == nil || len(f.parents) != len(f.parts) {
		return false
	}
	var current, root, pinned unix.Stat_t
	if unix.Fstat(int(f.file.Fd()), &current) != nil || !sameLinuxSignatureStamp(current, f.stamp) || unix.Lstat("/", &root) != nil || unix.Fstat(int(f.parents[0].Fd()), &pinned) != nil || root.Dev != pinned.Dev || root.Ino != pinned.Ino {
		return false
	}
	for i, parent := range f.parents {
		if !linuxSignatureDirectory(parent) {
			return false
		}
		next := f.file
		if i+1 < len(f.parents) {
			next = f.parents[i+1]
		}
		if unix.Fstatat(int(parent.Fd()), f.parts[i], &current, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(int(next.Fd()), &pinned) != nil || current.Dev != pinned.Dev || current.Ino != pinned.Ino || current.Mode&unix.S_IFMT != pinned.Mode&unix.S_IFMT {
			return false
		}
	}
	if f.stamp.Mode&unix.S_IFMT == unix.S_IFDIR {
		names, err := linuxSignatureNames(f.file)
		return err == nil && slices.Equal(names, f.names)
	}
	digest, err := linuxSignatureDigest(f.file, f.stamp.Size)
	return err == nil && digest == f.digest && unix.Fstat(int(f.file.Fd()), &current) == nil && sameLinuxSignatureStamp(current, f.stamp)
}

func sameLinuxSignatureStamp(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func linuxSignatureDigest(file *os.File, size int64) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	var block [32768]byte
	hash := sha256.New()
	for offset := int64(0); offset < size; {
		length := min(int64(len(block)), size-offset)
		n, err := file.ReadAt(block[:length], offset)
		if err != nil || int64(n) != length {
			return result, ErrUntrusted
		}
		hash.Write(block[:n])
		offset += int64(n)
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func (f *linuxSignatureFile) close() {
	if f.file != nil {
		f.file.Close()
		f.file = nil
	}
	for i := len(f.parents) - 1; i >= 0; i-- {
		f.parents[i].Close()
	}
	f.parents = nil
}
