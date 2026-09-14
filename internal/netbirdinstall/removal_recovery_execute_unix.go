//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"os"
	"path/filepath"
	"reflect"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

type removalRecoveryExecutionBackend struct {
	observe   func(context.Context) (*removalRecoveryOwnership, error)
	stop      func(context.Context, *removalRecoveryOwnership) error
	quiescent func(context.Context, string) error
	read      packageReader
	forget    func(context.Context) error
}

// The service configures inspection and journal admission together. Native
// recovery always continues the original stage identity.
func prepareNativeRemovalRecovery(ctx context.Context, originalID string, descriptor packageapi.Removal, digest string) (*Removal, error) {
	if !RemovalSupported() {
		return nil, ErrRemoval
	}
	return prepareRemovalRecovery(ctx, "/", 0, originalID, descriptor, digest, removalRecoveryExecutionBackend{
		observe: func(ctx context.Context) (*removalRecoveryOwnership, error) {
			return inspectNativeRemovalRecoveryOwnership(ctx, originalID, descriptor)
		},
		stop:      stopNativeRemovalRecovery,
		quiescent: nativeRemovalQuiescent,
		read:      readNativePackage,
		forget: func(ctx context.Context) error {
			return runNativeInstaller(ctx, "/usr/sbin/pkgutil", []string{"--volume", "/", "--forget", "io.netbird.client"})
		},
	})
}

func prepareRemovalRecovery(ctx context.Context, root string, owner uint32, originalID string, descriptor packageapi.Removal, digest string, backend removalRecoveryExecutionBackend) (*Removal, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || !netbirdcommand.ValidRequestID(originalID) || !descriptor.Valid() || descriptor.Platform != "macos" || !netbirdcommand.ValidDigest(digest) || backend.observe == nil || backend.stop == nil || backend.quiescent == nil || backend.read == nil || backend.forget == nil {
		return nil, ErrRemoval
	}
	observed, err := backend.observe(ctx)
	if err != nil || !matchesRemovalRecoveryReview(observed, originalID, descriptor, digest) {
		return nil, ErrRemoval
	}
	var held []*os.File
	closeHeld := func() error {
		var result error
		for _, file := range held {
			if file.Close() != nil {
				result = ErrRemoval
			}
		}
		held = nil
		return result
	}
	files, err := inspectRemovalRecoveryFilesHeld(ctx, root, owner, originalID, descriptor, &held)
	if err != nil || !reflect.DeepEqual(files, observed.files) {
		closeHeld()
		return nil, ErrRemoval
	}
	stagedApp := filepath.Join(root, "Applications", removalStagePrefix+originalID, removalApp)
	quiet := func(ctx context.Context) error { return backend.quiescent(ctx, stagedApp) }
	return &Removal{
		run: func(ctx context.Context) error {
			// The caller must durably admit a NEW recovery command before Run.
			// Native inspection alone cannot release or rewrite the original one.
			current, err := backend.observe(ctx)
			if err != nil || !matchesRemovalRecoveryReview(current, originalID, descriptor, digest) || !reflect.DeepEqual(current.files, files) || ctx.Err() != nil {
				return ErrRemoval
			}
			if backend.stop(ctx, current) != nil {
				return ErrRemoval
			}
			moved, err := moveRemovalRecoverySources(ctx, root, owner, current.files, quiet)
			if err != nil {
				return ErrRemoval
			}
			purged, err := purgeRemovalRecoveryPayload(ctx, root, owner, moved, quiet)
			if err != nil {
				return ErrRemoval
			}
			completed, err := completeRemovalRecoveryReceipts(ctx, root, owner, purged, removalRecoveryReceiptBackend{backend.read, backend.forget, quiet})
			if err != nil {
				return ErrRemoval
			}
			return finishRemovalRecoveryStage(ctx, root, owner, completed, backend.read, quiet)
		},
		close: closeHeld,
	}, nil
}

func matchesRemovalRecoveryReview(observed *removalRecoveryOwnership, originalID string, descriptor packageapi.Removal, digest string) bool {
	return observed != nil && observed.digest == digest && observed.files != nil && observed.files.manifest != nil && observed.files.manifest.manifest.RequestID == originalID && observed.files.manifest.manifest.Descriptor == descriptor && observed.processes != nil && observed.processes.requestID == originalID && observed.receipts != nil
}
