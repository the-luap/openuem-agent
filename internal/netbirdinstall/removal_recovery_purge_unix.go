//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// This private primitive only purges already relocated original payloads. Its
// admitted caller must stop runtime ownership, move remaining source roots and
// supply complete quiescence checks. Receipts and the manifest remain intact.
func purgeRemovalRecoveryPayload(ctx context.Context, root string, owner uint32, expected *removalRecoveryFiles, quiescent func(context.Context) error) (*removalRecoveryFiles, error) {
	if ctx == nil || ctx.Err() != nil || expected == nil || expected.manifest == nil || quiescent == nil {
		return nil, ErrRemoval
	}
	manifest := expected.manifest.manifest
	var held []*os.File
	defer func() {
		for _, file := range held {
			_ = file.Close()
		}
	}()
	current, err := inspectRemovalRecoveryFilesHeld(ctx, root, owner, manifest.RequestID, manifest.Descriptor, &held)
	if err != nil || !reflect.DeepEqual(current, expected) || !removalRecoverySourcesEmpty(current) {
		return nil, ErrRemoval
	}
	if quiescent(ctx) != nil || ctx.Err() != nil {
		return nil, ErrRemoval
	}
	prefix := "Applications/" + removalStagePrefix + manifest.RequestID
	stagePath := filepath.Join(root, prefix)
	// Index every parent at its full root-relative path. This namespace uses
	// ancestor accounting while still binding inode/device/mode/owner/ACL/flags
	// for every nested payload directory after its children have been deleted.
	parents := make(map[string]removalObject)
	for name, obj := range current.source {
		parents[name] = obj
	}
	for name, obj := range current.staged {
		if os.FileMode(obj.Mode).IsDir() {
			obj = removalRecoveryDirectory(obj)
		}
		parents[filepath.Join(prefix, name)] = obj
	}
	var names []string
	for name, obj := range current.staged {
		if removalPayload(name) && !obj.Missing {
			names = append(names, name)
		}
	}
	slices.SortFunc(names, func(a, b string) int {
		if depth := strings.Count(b, "/") - strings.Count(a, "/"); depth != 0 {
			return depth
		}
		return strings.Compare(b, a)
	})
	for _, name := range names {
		object := current.staged[name]
		dir := os.FileMode(object.Mode).IsDir()
		if dir {
			object = removalRecoveryDirectory(object)
		}
		full := filepath.Join(prefix, name)
		ancestry := removalSnapshotFor(ctx, root, owner, parents)
		parent, err := ancestry.parent(full)
		if err != nil {
			return nil, ErrRemoval
		}
		err = unlinkRemovalRecoveryPayload(ctx, stagePath, owner, name, object, ancestry, full, parent)
		closeErr := parent.Close()
		if err != nil || closeErr != nil {
			return nil, ErrRemoval
		}
		parents[full] = removalObject{Missing: true}
	}
	if quiescent(ctx) != nil || ctx.Err() != nil {
		return nil, ErrRemoval
	}
	after, err := inspectRemovalRecoveryFiles(ctx, root, owner, manifest.RequestID, manifest.Descriptor)
	if err != nil || !removalRecoverySourcesEmpty(after) || !reflect.DeepEqual(after.source, current.source) || !reflect.DeepEqual(after.manifest, current.manifest) || after.receipts != current.receipts {
		return nil, ErrRemoval
	}
	for name, obj := range after.staged {
		if removalPayload(name) && !obj.Missing {
			return nil, ErrRemoval
		}
	}
	return after, nil
}

func removalRecoverySourcesEmpty(files *removalRecoveryFiles) bool {
	if files == nil {
		return false
	}
	for _, name := range removalRoots {
		obj, ok := files.source[name]
		if !ok || !obj.Missing {
			return false
		}
	}
	return true
}

func removalRecoveryDirectory(obj removalObject) removalObject {
	obj.Size, obj.Modified, obj.Changed, obj.Links = 0, 0, 0, 0
	return obj
}

func unlinkRemovalRecoveryPayload(ctx context.Context, stage string, owner uint32, name string, expected removalObject, ancestry *removalSnapshot, full string, parent *os.File) error {
	dir := os.FileMode(expected.Mode).IsDir()
	check := removalSnapshotFor(ctx, stage, owner, map[string]removalObject{})
	defer clearRemovalData(check)
	actual, err := check.object(name, false, dir)
	if err != nil || actual != expected {
		return ErrRemoval
	}
	// Re-resolve the entire pinned ancestry after hashing. A directory moved
	// away and replaced cannot redirect the descriptor-relative unlink.
	repeated, err := ancestry.parent(full)
	if err != nil {
		return ErrRemoval
	}
	a, firstErr := parent.Stat()
	b, secondErr := repeated.Stat()
	closeErr := repeated.Close()
	if firstErr != nil || secondErr != nil || closeErr != nil || !os.SameFile(a, b) {
		return ErrRemoval
	}
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if os.FileMode(expected.Mode)&os.ModeSymlink != 0 {
		flags = removalSymlinkOpenFlags()
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(name), flags, 0)
	if err != nil {
		return ErrRemoval
	}
	entry := os.NewFile(uintptr(fd), name)
	info, err := entry.Stat()
	if err != nil || !sameRemovalInfo(expected, info, dir) || ctx.Err() != nil {
		_ = entry.Close()
		return ErrRemoval
	}
	flags = 0
	if dir {
		flags = unix.AT_REMOVEDIR
	}
	unlinkErr := unix.Unlinkat(int(parent.Fd()), filepath.Base(name), flags)
	syncErr := parent.Sync()
	closeErr = entry.Close()
	if unlinkErr != nil || syncErr != nil || closeErr != nil {
		return ErrRemoval
	}
	return nil
}
