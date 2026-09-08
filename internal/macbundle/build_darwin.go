package macbundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment/artifacts"
	"golang.org/x/sys/unix"
)

// Build accepts a trusted build workspace, retains its input/output directories,
// assembles an exclusive private staging tree and publishes with RENAME_EXCL.
// It never edits the source, signs code, invokes an installer or registers a job.
func Build(ctx context.Context, o Options) (Result, error) { return build(ctx, o, nil) }

// beforePublish permits deterministic interruption tests, never CLI injection.
func build(ctx context.Context, o Options, beforePublish func()) (result Result, resultErr error) {
	if ctx == nil || !validOptions(o) {
		return result, ErrOptions
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	source, sourceInfo, err := openChecked(o.Agent, false, false)
	if err != nil || sourceInfo.Size() < 1 || sourceInfo.Size() > artifacts.MaxPackageSize {
		if source != nil {
			source.Close()
		}
		return result, ErrSource
	}
	defer source.Close()
	if err := verifyMachO(io.NewSectionReader(source, 0, sourceInfo.Size()), o.Architecture); err != nil {
		return result, err
	}
	parent, parentInfo, err := openChecked(o.Output, true, true)
	if err != nil {
		return result, ErrOutput
	}
	defer parent.Close()
	root, err := os.OpenRoot(o.Output)
	if err != nil {
		return result, ErrOutput
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(parentInfo, opened) {
		return result, ErrOutput
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !unchanged(o.Output, parent, parentInfo, true, true) {
			return ErrOutput
		}
		if !unchanged(o.Agent, source, sourceInfo, false, false) {
			return ErrSource
		}
		return nil
	}
	if _, err := root.Lstat(BundleName); err == nil {
		return result, ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, ErrOutput
	}
	stage := ".openuem-macos-bundle-" + uuid.NewString()
	if err := root.Mkdir(stage, 0700); err != nil {
		return result, ErrBuild
	}
	owned, err := root.Lstat(stage)
	if err != nil {
		return result, ErrBuild
	}
	defer func() {
		// Never remove another operation's tree or an existing app bundle.
		if current, err := root.Lstat(stage); err == nil && os.SameFile(owned, current) {
			if err := root.RemoveAll(stage); err != nil && resultErr == nil {
				resultErr = ErrBuild
			}
		}
	}()
	tree, err := root.OpenRoot(stage)
	if err != nil {
		return result, ErrBuild
	}
	defer tree.Close()
	directories := []string{"Contents", "Contents/MacOS", "Contents/Library", "Contents/Library/LaunchDaemons"}
	for _, path := range directories {
		if err := tree.Mkdir(path, 0700); err != nil {
			return result, ErrBuild
		}
	}
	for path, data := range layout(o) {
		if err := writeFile(tree, path, data, 0644); err != nil {
			return result, ErrBuild
		}
	}
	image, err := tree.OpenFile(ExecutableRelative, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, ErrBuild
	}
	defer image.Close()
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(image, hash), contextReader{ctx, io.NewSectionReader(source, 0, sourceInfo.Size()+1)})
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err != nil || count != sourceInfo.Size() {
		return result, ErrSource
	}
	if err := image.Chmod(0755); err != nil {
		return result, ErrBuild
	}
	if err := image.Sync(); err != nil {
		return result, ErrBuild
	}
	if beforePublish != nil {
		beforePublish()
	}
	// Re-read both descriptors after copying; metadata alone cannot detect a
	// same-length source edit whose modification time was restored.
	for _, file := range []*os.File{source, image} {
		actual := sha256.New()
		count, err := io.Copy(actual, contextReader{ctx, io.NewSectionReader(file, 0, sourceInfo.Size()+1)})
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err != nil || count != sourceInfo.Size() || !bytes.Equal(hash.Sum(nil), actual.Sum(nil)) {
			return result, ErrSource
		}
	}
	if err := image.Close(); err != nil {
		return result, ErrBuild
	}
	// Set public code modes on owned descriptors, not existing user paths. The
	// output parent remains private while the release pipeline signs this tree.
	for _, path := range append(directories, ".") {
		directory, err := tree.Open(path)
		if err != nil {
			return result, ErrBuild
		}
		err = directory.Chmod(0755)
		if err == nil {
			err = directory.Sync()
		}
		closeErr := directory.Close()
		if err != nil || closeErr != nil {
			return result, ErrBuild
		}
	}
	if err := check(); err != nil {
		return result, err
	}
	if err := tree.Close(); err != nil {
		return result, ErrBuild
	}
	// Both names are relative to the same retained parent. An existing file,
	// directory or symlink wins publication and is never replaced.
	err = unix.RenameatxNp(int(parent.Fd()), stage, int(parent.Fd()), BundleName, unix.RENAME_EXCL)
	if errors.Is(err, os.ErrExist) || errors.Is(err, unix.ENOTEMPTY) {
		return result, ErrExists
	}
	if err != nil {
		return result, ErrBuild
	}
	result = Result{Published: true, Path: filepath.Join(o.Output, BundleName), Version: o.Version, Build: o.Build, Architecture: o.Architecture, RequiresReleaseSigning: true}
	if err := parent.Sync(); err != nil {
		return result, ErrDurability
	}
	return result, nil
}

func writeFile(root *os.Root, path string, data []byte, mode os.FileMode) error {
	file, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func openChecked(path string, directory, private bool) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !allowed(before, directory, private) {
		return nil, nil, ErrOutput
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !allowed(after, directory, private) {
		file.Close()
		return nil, nil, ErrOutput
	}
	return file, after, nil
}

func allowed(info os.FileInfo, directory, private bool) bool {
	if info == nil || directory != info.IsDir() || (!directory && !info.Mode().IsRegular()) {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	mask := os.FileMode(0022)
	if private {
		mask = 0077
	}
	return ok && (owner.Uid == 0 || owner.Uid == uint32(os.Geteuid())) && info.Mode().Perm()&mask == 0 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSymlink) == 0
}

func unchanged(path string, file *os.File, before os.FileInfo, directory, private bool) bool {
	entry, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, entry) || !allowed(entry, directory, private) {
		return false
	}
	current, err := file.Stat()
	return err == nil && os.SameFile(before, current) && allowed(current, directory, private) && (directory || current.Size() == before.Size() && current.ModTime().Equal(before.ModTime()))
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}
