package netbirdinstall

import (
	"context"

	"github.com/open-uem/nats/netbirdcommand"
)

// InspectRemovalAbsence verifies the complete current supported macOS package
// layout independently of any original manifest. Its fingerprint proves neither
// an earlier command's outcome nor authorization to clear a journal barrier.
func InspectRemovalAbsence(ctx context.Context) (string, error) {
	if ctx == nil || ctx.Err() != nil || !RemovalSupported() {
		return "", ErrRemoval
	}
	return nativeInspectRemovalAbsence(ctx)
}

// PrepareRemovalAbsence retains reviewed ancestry for a separate read-only
// verification. The caller owns journal admission and must join Run and Close.
// This is not a manifest continuation and cannot remove any remaining objects.
func PrepareRemovalAbsence(ctx context.Context, digest string) (*Removal, error) {
	if ctx == nil || ctx.Err() != nil || !RemovalSupported() || !netbirdcommand.ValidDigest(digest) {
		return nil, ErrRemoval
	}
	return prepareNativeRemovalAbsence(ctx, digest)
}
