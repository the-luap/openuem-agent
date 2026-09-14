package netbirdinstall

import (
	"context"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

// Recovery support requires the complete native observer and execution owner.
// The service additionally requires exact released original journal evidence.
func RemovalRecoverySupported() bool { return RemovalSupported() }

// InspectRemovalRecovery binds current files, receipts and runtime ownership to
// the protected original manifest. It does not interpret missing manifests as
// absence, release journal evidence, or authorize another execution attempt.
func InspectRemovalRecovery(ctx context.Context, originalID string, descriptor packageapi.Removal) (string, error) {
	if ctx == nil || ctx.Err() != nil || !RemovalRecoverySupported() || !netbirdcommand.ValidRequestID(originalID) || !descriptor.Valid() || descriptor.Platform != "macos" {
		return "", ErrRemoval
	}
	return nativeInspectRemovalRecovery(ctx, originalID, descriptor)
}

// PrepareRemovalRecovery acquires the reviewed original stage read-only. The
// caller must durably admit a separate recovery command before Run and retain
// the owner through joined Close. It never executes the original command again.
func PrepareRemovalRecovery(ctx context.Context, originalID string, descriptor packageapi.Removal, digest string) (*Removal, error) {
	if ctx == nil || ctx.Err() != nil || !RemovalRecoverySupported() || !netbirdcommand.ValidRequestID(originalID) || !descriptor.Valid() || descriptor.Platform != "macos" || !netbirdcommand.ValidDigest(digest) {
		return nil, ErrRemoval
	}
	return prepareNativeRemovalRecovery(ctx, originalID, descriptor, digest)
}
