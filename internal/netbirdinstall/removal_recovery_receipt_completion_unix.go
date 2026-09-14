//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"os"
	"reflect"
)

type removalRecoveryReceiptBackend struct {
	read      packageReader
	forget    func(context.Context) error
	quiescent func(context.Context) error
}

// Only after all reviewed payload has gone may receipt completion run. Native
// recognized records use fixed pkgutil forget; an unrecognized original orphan
// plist has a separate exact-file path and never masquerades as a native record.
func completeRemovalRecoveryReceipts(ctx context.Context, root string, owner uint32, expected *removalRecoveryFiles, backend removalRecoveryReceiptBackend) (*removalRecoveryFiles, error) {
	if ctx == nil || ctx.Err() != nil || expected == nil || expected.manifest == nil || backend.read == nil || backend.forget == nil || backend.quiescent == nil {
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
	if err != nil || !reflect.DeepEqual(current, expected) || !removalRecoveryPayloadEmpty(current) || backend.quiescent(ctx) != nil {
		return nil, ErrRemoval
	}
	receipts, err := inspectRemovalRecoveryReceipts(ctx, current, backend.read)
	if err != nil {
		return nil, ErrRemoval
	}
	// Native queries can take time. Recheck both the original receipts and the
	// entire retained stage immediately before any receipt mutation.
	before, err := inspectRemovalRecoveryFiles(ctx, root, owner, manifest.RequestID, manifest.Descriptor)
	if err != nil || !reflect.DeepEqual(before, current) || ctx.Err() != nil {
		return nil, ErrRemoval
	}
	switch receipts.kind {
	case "present", "bom-only":
		if backend.forget(ctx) != nil {
			return nil, ErrRemoval
		}
	case "plist-only":
		// pkgutil does not recognize or forget this orphan. It remains removable
		// only as the exact original manifest-bound file, after two successful
		// native absence queries and with no source/staged payload left.
		name := removalReceipt + ".plist"
		ancestry := removalSnapshotFor(ctx, root, owner, current.source)
		parent, err := ancestry.parent(name)
		if err != nil {
			return nil, ErrRemoval
		}
		err = unlinkRemovalRecoveryObject(ctx, root, owner, name, current.source[name], ancestry, name, parent)
		closeErr := parent.Close()
		if err != nil || closeErr != nil {
			return nil, ErrRemoval
		}
	case "absent":
	default:
		return nil, ErrRemoval
	}
	var after *removalRecoveryFiles
	for round := 0; round < 2; round++ {
		observed, err := inspectRemovalRecoveryFiles(ctx, root, owner, manifest.RequestID, manifest.Descriptor)
		if err != nil || !removalRecoveryPayloadEmpty(observed) || observed.receipts != "absent" || !reflect.DeepEqual(observed.manifest, current.manifest) || !reflect.DeepEqual(observed.staged, current.staged) {
			return nil, ErrRemoval
		}
		for name, obj := range current.source {
			if name != removalReceipt+".plist" && name != removalReceipt+".bom" && observed.source[name] != obj {
				return nil, ErrRemoval
			}
		}
		if backend.quiescent(ctx) != nil {
			return nil, ErrRemoval
		}
		proof, err := inspectRemovalRecoveryReceipts(ctx, observed, backend.read)
		if err != nil || proof.kind != "absent" || ctx.Err() != nil {
			return nil, ErrRemoval
		}
		if after != nil && !reflect.DeepEqual(after, observed) {
			return nil, ErrRemoval
		}
		after = observed
	}
	return after, nil
}

func removalRecoveryPayloadEmpty(files *removalRecoveryFiles) bool {
	if !removalRecoverySourcesEmpty(files) {
		return false
	}
	for _, name := range removalRoots {
		obj, ok := files.staged[name]
		if !ok || !obj.Missing {
			return false
		}
	}
	return true
}
