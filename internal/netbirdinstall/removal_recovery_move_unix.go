//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
)

// Continue only the original atomic root moves. Existing partial staged payload
// is preserved; each remaining source app still has to be complete and original.
func moveRemovalRecoverySources(ctx context.Context, root string, owner uint32, expected *removalRecoveryFiles, quiescent func(context.Context) error) (*removalRecoveryFiles, error) {
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
	if err != nil || !reflect.DeepEqual(current, expected) {
		return nil, ErrRemoval
	}
	if quiescent(ctx) != nil || ctx.Err() != nil {
		return nil, ErrRemoval
	}
	prefix := "Applications/" + removalStagePrefix + manifest.RequestID
	stagePath := filepath.Join(root, prefix)
	moved := map[string]bool{}
	for _, name := range removalRoots {
		if current.source[name].Missing {
			continue
		}
		if !current.staged[name].Missing {
			return nil, ErrRemoval
		}
		if createRemovalRecoveryParents(ctx, root, owner, current, name, &held) != nil {
			return nil, ErrRemoval
		}
		ancestry := removalSnapshotFor(ctx, root, owner, removalRecoveryRootObjects(current))
		from, err := ancestry.parent(name)
		if err != nil {
			return nil, ErrRemoval
		}
		to, err := ancestry.parent(filepath.Join(prefix, name))
		if err != nil {
			from.Close()
			return nil, ErrRemoval
		}
		err = moveRemovalRecoveryRoot(ctx, root, stagePath, owner, current, name, ancestry, from, to, &held)
		fromSync, toSync := from.Sync(), to.Sync()
		fromClose, toClose := from.Close(), to.Close()
		if err != nil || fromSync != nil || toSync != nil || fromClose != nil || toClose != nil {
			return nil, ErrRemoval
		}
		moved[name] = true
	}
	if quiescent(ctx) != nil || ctx.Err() != nil {
		return nil, ErrRemoval
	}
	after, err := inspectRemovalRecoveryFiles(ctx, root, owner, manifest.RequestID, manifest.Descriptor)
	if err != nil || !removalRecoverySourcesEmpty(after) || !reflect.DeepEqual(current.manifest, after.manifest) || current.receipts != after.receipts {
		return nil, ErrRemoval
	}
	for name, obj := range current.source {
		if !removalPayload(name) && after.source[name] != obj {
			return nil, ErrRemoval
		}
	}
	for name, obj := range current.staged {
		if !moved[name] && !(moved[removalApp] && strings.HasPrefix(name, removalApp+"/")) && after.staged[name] != obj {
			return nil, ErrRemoval
		}
	}
	return after, nil
}

func removalRecoveryRootObjects(files *removalRecoveryFiles) map[string]removalObject {
	prefix := "Applications/" + removalStagePrefix + files.manifest.manifest.RequestID
	objects := maps.Clone(files.source)
	for name, obj := range files.staged {
		if os.FileMode(obj.Mode).IsDir() {
			obj = removalRecoveryDirectory(obj)
		}
		objects[filepath.Join(prefix, name)] = obj
	}
	return objects
}

func createRemovalRecoveryParents(ctx context.Context, root string, owner uint32, current *removalRecoveryFiles, name string, held *[]*os.File) error {
	prefix := "Applications/" + removalStagePrefix + current.manifest.manifest.RequestID
	parts := strings.Split(filepath.Dir(name), "/")
	for count := 1; count <= len(parts); count++ {
		parentName := strings.Join(parts[:count], "/")
		obj, ok := current.staged[parentName]
		if !ok {
			return ErrRemoval
		}
		if !obj.Missing {
			continue
		}
		full := filepath.Join(prefix, parentName)
		ancestry := removalSnapshotFor(ctx, root, owner, removalRecoveryRootObjects(current))
		parent, err := ancestry.parent(full)
		if err != nil {
			return ErrRemoval
		}
		err = unix.Mkdirat(int(parent.Fd()), filepath.Base(parentName), 0700)
		syncErr, closeErr := parent.Sync(), parent.Close()
		if err != nil || syncErr != nil || closeErr != nil {
			return ErrRemoval
		}
		check := removalSnapshotFor(ctx, filepath.Join(root, prefix), owner, current.staged)
		check.held = held
		created, err := check.object(parentName, false, true)
		if err != nil || created.Mode != uint32(os.ModeDir|0700) || created.UID != owner {
			return ErrRemoval
		}
		current.staged[parentName] = created
	}
	return nil
}

func moveRemovalRecoveryRoot(ctx context.Context, root, stage string, owner uint32, current *removalRecoveryFiles, name string, ancestry *removalSnapshot, from, to *os.File, held *[]*os.File) error {
	source := removalSnapshotFor(ctx, root, owner, current.source)
	defer clearRemovalData(source)
	obj, err := source.object(name, false, false)
	if err != nil || obj != current.source[name] || ctx.Err() != nil {
		return ErrRemoval
	}
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if os.FileMode(obj.Mode)&os.ModeSymlink != 0 {
		flags = removalSymlinkOpenFlags()
	}
	fd, err := unix.Openat(int(from.Fd()), filepath.Base(name), flags, 0)
	if err != nil {
		return ErrRemoval
	}
	entry := os.NewFile(uintptr(fd), name)
	defer entry.Close()
	info, err := entry.Stat()
	if err != nil || !sameRemovalInfo(obj, info, false) || ctx.Err() != nil {
		return ErrRemoval
	}
	if renameRemovalExclusive(int(from.Fd()), filepath.Base(name), int(to.Fd()), filepath.Base(name)) != nil {
		return ErrRemoval
	}
	anchors := make(map[string]removalObject)
	for _, parent := range removalStageParents {
		anchors[parent] = current.staged[parent]
	}
	capture := &removalStaging{path: stage, owner: owner, anchors: anchors, original: current.manifest.manifest.Objects}
	_, err = capture.capture(ctx, name)
	*held = append(*held, capture.held...)
	capture.held = nil
	if err == nil {
		return nil
	}
	// Return a rejected moved root only to the same protected, still-empty
	// source slot. Never overwrite a source replacement or remove unknown data.
	check, checkErr := ancestry.parent(name)
	if checkErr == nil {
		a, e1 := check.Stat()
		b, e2 := from.Stat()
		var staged unix.Stat_t
		sameRoot := unix.Fstatat(int(to.Fd()), filepath.Base(name), &staged, unix.AT_SYMLINK_NOFOLLOW) == nil && uint64(staged.Ino) == obj.Inode && uint64(staged.Dev) == obj.Device
		if e1 == nil && e2 == nil && os.SameFile(a, b) && sameRoot {
			_ = renameRemovalExclusive(int(to.Fd()), filepath.Base(name), int(from.Fd()), filepath.Base(name))
		}
		check.Close()
	}
	return ErrRemoval
}
