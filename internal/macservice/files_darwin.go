package macservice

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/open-uem/openuem-agent/internal/macbundle"
	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/unix"
)

type bundleFiles struct {
	uid                            uint32
	files                          []*os.File
	info, daemon, seal             *os.File
	infoData, daemonData, sealData []byte
	ancestors                      []*os.File
}

func trustedAncestor(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode().Perm()&0002 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	// Standard /Applications is root:admin 0775. System administrators are
	// trusted installation actors, as they are for the Windows installer.
	return ok && owner.Uid == 0 && (info.Mode().Perm()&0020 == 0 || owner.Gid == 0 || owner.Gid == 80)
}

func protected(info os.FileInfo, directory bool, uid uint32) bool {
	if info == nil || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uid
}

func openCode(path string, directory bool, uid uint32) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || !protected(before, directory, uid) {
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
	if err != nil || !os.SameFile(before, after) || !protected(after, directory, uid) {
		file.Close()
		return nil, ErrAccess
	}
	return file, nil
}

// Production uses the fixed root-owned /Applications installation. Fixture
// helpers use owned temporary bundles and never call native registration.
func inspectBundle(path string, uid uint32) (_ *bundleFiles, resultErr error) {
	if !nativepath.Valid(path) {
		return nil, ErrAccess
	}
	b := &bundleFiles{uid: uid}
	defer func() {
		if resultErr != nil {
			b.Close()
		}
	}()
	directories := []string{path, filepath.Join(path, "Contents"), filepath.Join(path, "Contents/MacOS"), filepath.Join(path, "Contents/Library"), filepath.Join(path, "Contents/Library/LaunchDaemons"), filepath.Join(path, "Contents/_CodeSignature")}
	// The production path has only these two ancestors. Both remain retained.
	if path == macbundle.InstallationPath {
		for _, ancestor := range []string{"/", "/Applications"} {
			before, err := os.Lstat(ancestor)
			if err != nil || !trustedAncestor(before) {
				return nil, ErrAccess
			}
			fd, err := unix.Open(ancestor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return nil, ErrAccess
			}
			file := os.NewFile(uintptr(fd), ancestor)
			b.ancestors = append(b.ancestors, file)
			after, err := file.Stat()
			if err != nil || !os.SameFile(before, after) || !trustedAncestor(after) {
				return nil, ErrAccess
			}
		}
	}
	for _, directory := range directories {
		file, err := openCode(directory, true, uid)
		if err != nil {
			return nil, err
		}
		b.files = append(b.files, file)
	}
	for _, name := range []string{macbundle.ExecutableRelative, "Contents/Info.plist", macbundle.DaemonRelative, "Contents/_CodeSignature/CodeResources"} {
		file, err := openCode(filepath.Join(path, name), false, uid)
		if err != nil {
			return nil, err
		}
		b.files = append(b.files, file)
		if name == "Contents/Info.plist" {
			b.info = file
		}
		if name == macbundle.DaemonRelative {
			b.daemon = file
		}
		if name == "Contents/_CodeSignature/CodeResources" {
			b.seal = file
		}
	}
	var err error
	b.infoData, err = metadata(b.info)
	if err != nil {
		return nil, err
	}
	b.daemonData, err = metadata(b.daemon)
	if err != nil || macbundle.ValidateMetadata(b.infoData, b.daemonData) != nil {
		return nil, ErrAccess
	}
	b.sealData, err = metadataLimit(b.seal, 1<<20)
	if err != nil {
		return nil, err
	}
	if err := b.Check(); err != nil {
		return nil, err
	}
	return b, nil
}

func metadata(file *os.File) ([]byte, error) {
	return metadataLimit(file, 32<<10)
}

func metadataLimit(file *os.File, limit int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || info.Size() < 1 || info.Size() > limit {
		return nil, ErrAccess
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, info.Size()), data); err != nil {
		return nil, ErrAccess
	}
	return data, nil
}

func (b *bundleFiles) Check() error {
	if b == nil || len(b.files) == 0 {
		return ErrAccess
	}
	for _, file := range b.ancestors {
		opened, err := file.Stat()
		current, entryErr := os.Lstat(file.Name())
		if err != nil || entryErr != nil || !os.SameFile(opened, current) || !trustedAncestor(opened) || !trustedAncestor(current) {
			return ErrAccess
		}
	}
	for _, file := range b.files {
		opened, err := file.Stat()
		current, entryErr := os.Lstat(file.Name())
		if err != nil || entryErr != nil || !os.SameFile(opened, current) || !protected(opened, opened.IsDir(), b.uid) || !protected(current, opened.IsDir(), b.uid) {
			return ErrAccess
		}
	}
	info, infoErr := metadata(b.info)
	daemon, daemonErr := metadata(b.daemon)
	seal, sealErr := metadataLimit(b.seal, 1<<20)
	if infoErr != nil || daemonErr != nil || sealErr != nil || !bytes.Equal(info, b.infoData) || !bytes.Equal(daemon, b.daemonData) || !bytes.Equal(seal, b.sealData) {
		return ErrAccess
	}
	return nil
}

func (b *bundleFiles) Close() error {
	var first error
	for _, file := range append(b.files, b.ancestors...) {
		if err := file.Close(); err != nil && first == nil {
			first = err
		}
	}
	b.files = nil
	b.ancestors = nil
	return first
}
