//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

func finishRemovalRecoveryStage(ctx context.Context, root string, owner uint32, expected *removalRecoveryFiles, read packageReader, quiescent func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || expected == nil || expected.manifest == nil || read == nil || quiescent == nil {
		return ErrRemoval
	}
	manifest := expected.manifest.manifest
	var held []*os.File
	defer func() {
		for _, file := range held {
			_ = file.Close()
		}
	}()
	current, err := inspectRemovalRecoveryFilesHeld(ctx, root, owner, manifest.RequestID, manifest.Descriptor, &held)
	if err != nil || !reflect.DeepEqual(current, expected) || !removalRecoveryPayloadEmpty(current) || current.receipts != "absent" {
		return ErrRemoval
	}
	for round := 0; round < 2; round++ {
		if removalSourcesAbsent(ctx, root, owner, false) != nil || quiescent(ctx) != nil {
			return ErrRemoval
		}
		if present, err := nativeRemovalReceiptPresent(ctx, read); err != nil || present {
			return ErrRemoval
		}
	}
	prefix := "Applications/" + removalStagePrefix + manifest.RequestID
	stage := filepath.Join(root, prefix)
	objects := removalRecoveryRootObjects(current)
	for i := len(removalStageParents) - 1; i > 0; i-- {
		name := removalStageParents[i]
		if current.staged[name].Missing {
			continue
		}
		full := filepath.Join(prefix, name)
		ancestry := removalSnapshotFor(ctx, root, owner, objects)
		parent, err := ancestry.parent(full)
		if err != nil {
			return ErrRemoval
		}
		err = unlinkRemovalRecoveryObject(ctx, stage, owner, name, current.staged[name], ancestry, full, parent)
		closeErr := parent.Close()
		if err != nil || closeErr != nil {
			return ErrRemoval
		}
		objects[full] = removalObject{Missing: true}
	}
	// Preserve the manifest until every scaffold is gone and its directory has
	// no unknown children. Reinspection still binds the same original objects.
	after, err := inspectRemovalRecoveryFiles(ctx, root, owner, manifest.RequestID, manifest.Descriptor)
	if err != nil || !removalRecoveryPayloadEmpty(after) || after.receipts != "absent" || !reflect.DeepEqual(after.source, current.source) || !reflect.DeepEqual(after.manifest, current.manifest) {
		return ErrRemoval
	}
	ancestry := removalSnapshotFor(ctx, root, owner, objects)
	full := filepath.Join(prefix, "manifest.json")
	directory, err := ancestry.parent(full)
	if err != nil {
		return ErrRemoval
	}
	names, readErr := directory.Readdirnames(2)
	if readErr != nil && readErr != io.EOF || len(names) != 1 || names[0] != "manifest.json" {
		directory.Close()
		return ErrRemoval
	}
	if quiescent(ctx) != nil {
		directory.Close()
		return ErrRemoval
	}
	if present, err := nativeRemovalReceiptPresent(ctx, read); err != nil || present {
		directory.Close()
		return ErrRemoval
	}
	err = unlinkRemovalRecoveryObject(ctx, stage, owner, "manifest.json", current.manifest.file, ancestry, full, directory)
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		return ErrRemoval
	}
	parent, err := ancestry.parent(prefix)
	if err != nil {
		return ErrRemoval
	}
	err = unlinkRemovalRecoveryObject(ctx, root, owner, prefix, current.manifest.directory, ancestry, prefix, parent)
	closeErr = parent.Close()
	if err != nil || closeErr != nil {
		return ErrRemoval
	}
	return verifyNativeRemovalAbsence(ctx, root, owner, read, func(context.Context, string) error { return quiescent(ctx) })
}
