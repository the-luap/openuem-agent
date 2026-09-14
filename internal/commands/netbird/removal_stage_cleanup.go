package netbird

import (
	"context"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-agent/internal/netbirdinstall"
)

type removalStageCleanupOwner struct {
	inspect func(context.Context, string) (netbirdinstall.RemovalStageCleanupReview, error)
	prepare func(context.Context, string, netbirdinstall.RemovalStageCleanupReview) (nativeRemoval, error)
}

func (s *DurableService) removalStageCleanupState(ctx context.Context, c netbirdcommand.ControlRequest) netbirdcommand.ControlResponse {
	r, _ := netbirdcommand.ControlResponseFor(c, "unavailable")
	p := s.removalStageCleanup
	if p == nil || p.inspect == nil || p.prepare == nil || s.executor.cleanupRemovalStage == nil || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || c.Version != netbirdcommand.RemovalStageCleanupInspectionVersion || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
		return r
	}
	if !s.executor.mu.TryLock() {
		r.Outcome = "blocked"
		return r
	}
	defer s.executor.mu.Unlock()
	original := c.RemovalStageCleanupOriginal
	state, err := s.journal.RemovalStageCleanupState(c.Identity, original, time.Now())
	if err != nil {
		r.Outcome = recoveryJournalOutcome(err)
		return r
	}
	review, err := p.inspect(ctx, original.RequestID)
	if err != nil || !review.Valid() || ctx.Err() != nil || s.ctx.Err() != nil || !c.Executable(s.identity, time.Now()) {
		return r
	}
	after, err := s.journal.RemovalStageCleanupState(c.Identity, original, time.Now())
	if err != nil {
		r.Outcome = recoveryJournalOutcome(err)
		return r
	}
	if after != state {
		r.Outcome = "blocked"
		return r
	}
	r.Outcome, r.State = "ok", state
	r.RemovalStageCleanup = netbirdcommand.RemovalStageCleanup{Original: original, Profile: netbirdcommand.RemovalStageCleanupProfile, JournalRevision: state.Revision, StateDigest: review.StateDigest, DirectoryCount: review.DirectoryCount, ManifestPresent: review.ManifestPresent, ManifestBytes: review.ManifestBytes}
	return r
}

func prepareNativeRemovalStageCleanup(ctx context.Context, originalID string, review netbirdinstall.RemovalStageCleanupReview) (nativeRemoval, error) {
	return netbirdinstall.PrepareRemovalStageCleanup(ctx, originalID, review)
}

// The common executor owns the mutex through acquisition, admission, Run and
// Close. Every expensive native observation is bracketed by the same original
// release and current journal revision. Journal admission records this separate
// current-state cleanup.
func (s *DurableService) acquireRemovalStageCleanup(ctx context.Context, c netbirdcommand.Command) (*nativePackageLease, error) {
	p := s.removalStageCleanup
	if p == nil || p.inspect == nil || p.prepare == nil || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || c.Version != netbirdcommand.RemovalStageCleanupVersion || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
		return nil, ErrInvalidAction
	}
	original := c.RemovalStageCleanup.Original
	state, err := s.journal.RemovalStageCleanupState(c.Identity, original, time.Now())
	if err != nil || state.Revision != c.RemovalStageCleanup.JournalRevision {
		return nil, ErrActionUnconfirmed
	}
	native, err := p.prepare(ctx, original.RequestID, removalStageCleanupReview(c.RemovalStageCleanup))
	if err != nil || native == nil {
		if native != nil {
			_ = native.Close()
		}
		return nil, ErrActionUnconfirmed
	}
	after, err := s.journal.RemovalStageCleanupState(c.Identity, original, time.Now())
	if err != nil || after != state || ctx.Err() != nil || s.ctx.Err() != nil || !c.Executable(s.identity, time.Now()) {
		_ = native.Close()
		return nil, ErrActionUnconfirmed
	}
	return &nativePackageLease{revision: state.Revision, run: native.Run, release: native.Close}, nil
}

func removalStageCleanupReview(r netbirdcommand.RemovalStageCleanup) netbirdinstall.RemovalStageCleanupReview {
	return netbirdinstall.RemovalStageCleanupReview{StateDigest: r.StateDigest, DirectoryCount: r.DirectoryCount, ManifestPresent: r.ManifestPresent, ManifestBytes: r.ManifestBytes}
}
