package bootstrapinstall

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"runtime"
	"strings"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/unix"
)

type linuxCodeIdentity struct {
	image       *os.File
	directories []*os.File
	parts       []string
	stamp       unix.Stat_t
	digest      [sha256.Size]byte
}

func openLinuxRunningAgent() (*Executable, error) {
	if os.Geteuid() != 0 {
		return nil, ErrPackage
	}
	// This one deliberate procfs magic-link open is kernel-selected, never a
	// caller path. Its inode must match the separately retained canonical path.
	image, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, ErrPackage
	}
	path, err := os.Executable()
	if err != nil {
		image.Close()
		return nil, ErrPackage
	}
	return openLinuxCodeIdentity(path, image)
}

// image ownership transfers on both success and failure. The public entry point
// supplies only its kernel-selected executable; fixtures use independent files.
func openLinuxCodeIdentity(path string, image *os.File) (*Executable, error) {
	c := &linuxCodeIdentity{image: image}
	var file *os.File
	accepted := false
	defer func() {
		if !accepted {
			if file != nil {
				file.Close()
			}
			c.close()
		}
	}()
	if image == nil || os.Geteuid() != 0 || !nativepath.Valid(path) || path == "/" {
		return nil, ErrPackage
	}
	c.parts = strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrPackage
	}
	parent := os.NewFile(uintptr(fd), "/")
	c.directories = append(c.directories, parent)
	for i, part := range c.parts {
		if !linuxCodeDirectory(parent) {
			return nil, ErrPackage
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(c.parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		fd, err = unix.Openat(int(parent.Fd()), part, flags, 0)
		if err != nil {
			return nil, ErrPackage
		}
		opened := os.NewFile(uintptr(fd), part)
		if i == len(c.parts)-1 {
			file = opened
		} else {
			c.directories = append(c.directories, opened)
			parent = opened
		}
	}
	if unix.Fstat(int(file.Fd()), &c.stamp) != nil || c.stamp.Mode&unix.S_IFMT != unix.S_IFREG || c.stamp.Uid != 0 || c.stamp.Nlink != 1 || c.stamp.Mode&07022 != 0 || c.stamp.Mode&0100 == 0 || c.stamp.Size < 64 || c.stamp.Size > artifacts.MaxPackageSize {
		return nil, ErrPackage
	}
	var header [64]byte
	if _, err = file.ReadAt(header[:], 0); err != nil || !linuxNativeELF(header[:]) {
		return nil, ErrPackage
	}
	c.digest, err = linuxCodeDigest(file, c.stamp.Size)
	if err != nil || !c.valid(file) {
		return nil, ErrPackage
	}
	info, err := file.Stat()
	if err != nil {
		return nil, ErrPackage
	}
	accepted = true
	return &Executable{path: path, file: file, info: info, code: c}, nil
}

func linuxNativeELF(header []byte) bool {
	if len(header) != 64 || string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 || header[7] != 0 && header[7] != 3 || binary.LittleEndian.Uint32(header[20:24]) != 1 || binary.LittleEndian.Uint16(header[52:54]) != 64 {
		return false
	}
	typeID := binary.LittleEndian.Uint16(header[16:18])
	if typeID != 2 && typeID != 3 {
		return false
	}
	machine := binary.LittleEndian.Uint16(header[18:20])
	return runtime.GOARCH == "amd64" && machine == 62 || runtime.GOARCH == "arm64" && machine == 183
}

func linuxCodeDirectory(file *os.File) bool {
	var st unix.Stat_t
	return unix.Fstat(int(file.Fd()), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == 0 && st.Mode&07022 == 0
}

func (c *linuxCodeIdentity) valid(file *os.File) bool {
	if c == nil || c.image == nil || file == nil || len(c.directories) != len(c.parts) {
		return false
	}
	var current, running, root, pinned unix.Stat_t
	if unix.Fstat(int(file.Fd()), &current) != nil || !sameLinuxCodeStamp(current, c.stamp) || unix.Fstat(int(c.image.Fd()), &running) != nil || !sameLinuxCodeStamp(running, c.stamp) || unix.Lstat("/", &root) != nil || unix.Fstat(int(c.directories[0].Fd()), &pinned) != nil || root.Dev != pinned.Dev || root.Ino != pinned.Ino {
		return false
	}
	for i, directory := range c.directories {
		if !linuxCodeDirectory(directory) {
			return false
		}
		next := file
		if i+1 < len(c.directories) {
			next = c.directories[i+1]
		}
		if unix.Fstatat(int(directory.Fd()), c.parts[i], &current, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(int(next.Fd()), &pinned) != nil || current.Dev != pinned.Dev || current.Ino != pinned.Ino || current.Mode&unix.S_IFMT != pinned.Mode&unix.S_IFMT {
			return false
		}
	}
	digest, err := linuxCodeDigest(file, c.stamp.Size)
	return err == nil && digest == c.digest && unix.Fstat(int(file.Fd()), &current) == nil && sameLinuxCodeStamp(current, c.stamp)
}

func sameLinuxCodeStamp(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func linuxCodeDigest(file *os.File, size int64) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	var buffer [32768]byte
	hash := sha256.New()
	for offset := int64(0); offset < size; {
		length := min(int64(len(buffer)), size-offset)
		n, err := file.ReadAt(buffer[:length], offset)
		if err != nil || int64(n) != length {
			return digest, ErrPackage
		}
		hash.Write(buffer[:n])
		offset += int64(n)
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func (c *linuxCodeIdentity) close() error {
	var result error
	if c.image != nil {
		result = c.image.Close()
		c.image = nil
	}
	for i := len(c.directories) - 1; i >= 0; i-- {
		if err := c.directories[i].Close(); result == nil {
			result = err
		}
	}
	c.directories = nil
	return result
}
