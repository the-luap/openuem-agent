package netbirdinstall

import (
	"context"

	"github.com/open-uem/nats/netbirdcommand"
)

// RemovalStageCleanupReview is the source-free current scope of a separately
// reviewed cleanup. It grants no original journal ownership or replay authority.
type RemovalStageCleanupReview struct {
	StateDigest     string
	DirectoryCount  int
	ManifestPresent bool
	ManifestBytes   int64
}

func (r RemovalStageCleanupReview) Valid() bool {
	return netbirdcommand.ValidDigest(r.StateDigest) && r.DirectoryCount >= 1 && r.DirectoryCount <= 7 && r.ManifestBytes >= 0 && r.ManifestBytes <= 2<<20 && (r.ManifestPresent || r.ManifestBytes == 0)
}

// InspectRemovalStageCleanup reads only the selected current private scaffold,
// current supported package absence and complete runtime/receipt evidence. A
// complete usable manifest or any unknown object prevents this cleanup review.
func InspectRemovalStageCleanup(ctx context.Context, originalID string) (RemovalStageCleanupReview, error) {
	if ctx == nil || ctx.Err() != nil || !RemovalSupported() || !netbirdcommand.ValidRequestID(originalID) {
		return RemovalStageCleanupReview{}, ErrRemoval
	}
	return nativeInspectRemovalStageCleanup(ctx, originalID)
}

// PrepareRemovalStageCleanup retains the exact reviewed objects without mutation.
// The caller must prove original release, admit a distinct command and join Run
// and Close. Completion describes this cleanup, never the original uninstall.
func PrepareRemovalStageCleanup(ctx context.Context, originalID string, review RemovalStageCleanupReview) (*Removal, error) {
	if ctx == nil || ctx.Err() != nil || !RemovalSupported() || !netbirdcommand.ValidRequestID(originalID) || !review.Valid() {
		return nil, ErrRemoval
	}
	return prepareNativeRemovalStageCleanup(ctx, originalID, review)
}
