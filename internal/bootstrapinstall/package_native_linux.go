package bootstrapinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
	"github.com/open-uem/openuem-agent/internal/nativepath"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
	"golang.org/x/sys/unix"
)

type linuxPackageDirectory struct {
	parts       []string
	directories []*os.File
}

func stageNativePackage(ctx context.Context, verified *bootstrap.Verified, client *enrollment.HTTPClient, root string, checkpoint artifacts.Checkpoint) (*Package, error) {
	return stagePackageWithOwner(ctx, verified, client, root, checkpoint, packagesignature.Verify, prepareLinuxPackageDirectory)
}

// The public Linux staging path retains every directory before any download.
// Existing unsafe roots are rejected without creating or repairing their trees.
func prepareLinuxPackageDirectory(p *Package) error {
	root := filepath.Dir(p.directory)
	if os.Geteuid() != 0 || !nativepath.Valid(root) || root == "/" {
		return ErrPackage
	}
	owner := &linuxPackageDirectory{parts: strings.Split(strings.TrimPrefix(root, "/"), "/")}
	accepted := false
	defer func() {
		if !accepted {
			owner.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrPackage
	}
	parent := os.NewFile(uintptr(fd), "/")
	owner.directories = append(owner.directories, parent)
	for _, part := range owner.parts {
		if !linuxCodeDirectory(parent) {
			return ErrPackage
		}
		fd, err = unix.Openat(int(parent.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return ErrPackage
		}
		parent = os.NewFile(uintptr(fd), part)
		owner.directories = append(owner.directories, parent)
	}
	if !owner.validChain(1) {
		return ErrPackage
	}
	name := filepath.Base(p.directory)
	if err = unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return ErrPackage
	}
	// If this open fails, preserve the private fragment: no observed inode yet
	// exists to authorize removal. Never recursively clean an uncertain path.
	fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrPackage
	}
	owner.parts = append(owner.parts, name)
	owner.directories = append(owner.directories, os.NewFile(uintptr(fd), name))
	if !owner.valid() {
		return ErrPackage
	}
	p.directoryOwner = owner
	accepted = true
	return nil
}

func (d *linuxPackageDirectory) valid() bool { return d.validChain(2) }

func (d *linuxPackageDirectory) validChain(privateCount int) bool {
	if d == nil || len(d.directories) != len(d.parts)+1 || len(d.directories) <= privateCount {
		return false
	}
	var actual, pinned unix.Stat_t
	if unix.Lstat("/", &actual) != nil || unix.Fstat(int(d.directories[0].Fd()), &pinned) != nil || actual.Dev != pinned.Dev || actual.Ino != pinned.Ino {
		return false
	}
	for i, directory := range d.directories {
		if !linuxCodeDirectory(directory) || unix.Fstat(int(directory.Fd()), &pinned) != nil {
			return false
		}
		if i >= len(d.directories)-privateCount && pinned.Mode&07777 != 0700 {
			return false
		}
		if i > 0 {
			if unix.Fstatat(int(d.directories[i-1].Fd()), d.parts[i-1], &actual, unix.AT_SYMLINK_NOFOLLOW) != nil || actual.Mode&unix.S_IFMT != unix.S_IFDIR || actual.Dev != pinned.Dev || actual.Ino != pinned.Ino {
				return false
			}
		}
	}
	return true
}

func (d *linuxPackageDirectory) validFile(name string, original os.FileInfo) bool {
	if !d.valid() || original == nil || filepath.Base(name) != name || name == "." || name == ".." {
		return false
	}
	expected, ok := original.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	var actual unix.Stat_t
	return unix.Fstatat(int(d.directories[len(d.directories)-1].Fd()), name, &actual, unix.AT_SYMLINK_NOFOLLOW) == nil && actual.Mode&unix.S_IFMT == unix.S_IFREG && actual.Mode&07777 == 0600 && actual.Uid == 0 && actual.Nlink == 1 && actual.Dev == expected.Dev && actual.Ino == expected.Ino
}

func (d *linuxPackageDirectory) cleanup(name string, original os.FileInfo) error {
	if !d.valid() {
		return ErrPackage
	}
	stage := d.directories[len(d.directories)-1]
	if original != nil {
		var entry unix.Stat_t
		err := unix.Fstatat(int(stage.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
		if !errors.Is(err, unix.ENOENT) {
			if err != nil || !d.validFile(name, original) || unix.Unlinkat(int(stage.Fd()), name, 0) != nil {
				return ErrPackage
			}
		}
	}
	if !d.valid() {
		return ErrPackage
	}
	root := d.directories[len(d.directories)-2]
	if unix.Unlinkat(int(root.Fd()), d.parts[len(d.parts)-1], unix.AT_REMOVEDIR) != nil {
		return ErrPackage
	}
	return nil
}

func (d *linuxPackageDirectory) close() error {
	var result error
	for i := len(d.directories) - 1; i >= 0; i-- {
		if err := d.directories[i].Close(); result == nil {
			result = err
		}
	}
	d.directories = nil
	return result
}
