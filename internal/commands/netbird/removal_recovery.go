package netbird

import (
	"context"
	"errors"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
)

type removalRecoveryOwner struct {
	inspect func(context.Context, string, packageapi.Removal) (string, error)
	prepare func(context.Context, string, packageapi.Removal, string) (nativeRemoval, error)
}

func recoveryJournalOutcome(err error) string {
	switch {
	case errors.Is(err, netbirdjournal.ErrMissing):
		return "missing"
	case errors.Is(err, netbirdjournal.ErrConflict):
		return "conflict"
	case errors.Is(err, netbirdjournal.ErrPending), errors.Is(err, netbirdjournal.ErrFull):
		return "blocked"
	default:
		return "unavailable"
	}
}

func (s *DurableService) removalRecoveryState(ctx context.Context, c netbirdcommand.ControlRequest) netbirdcommand.ControlResponse {
	r, _ := netbirdcommand.ControlResponseFor(c, "unavailable")
	p := s.removalRecovery
	if p == nil || p.inspect == nil || p.prepare == nil || s.executor.recoverRemoval == nil || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || c.Version != netbirdcommand.RemovalRecoveryInspectionVersion || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
		return r
	}
	if !s.executor.mu.TryLock() {
		r.Outcome = "blocked"
		return r
	}
	defer s.executor.mu.Unlock()
	original := c.RemovalRecoveryOriginal
	state, err := s.journal.RemovalRecoveryState(c.Identity, original, time.Now())
	if err != nil {
		r.Outcome = recoveryJournalOutcome(err)
		return r
	}
	digest, err := p.inspect(ctx, original.RequestID, original.Removal)
	if err != nil || !netbirdcommand.ValidDigest(digest) || ctx.Err() != nil || s.ctx.Err() != nil || !c.Executable(s.identity, time.Now()) {
		return r
	}
	after, err := s.journal.RemovalRecoveryState(c.Identity, original, time.Now())
	if err != nil {
		r.Outcome = recoveryJournalOutcome(err)
		return r
	}
	if after != state {
		r.Outcome = "blocked"
		return r
	}
	r.Outcome, r.State = "ok", state
	r.RemovalRecovery = netbirdcommand.RemovalRecovery{Original: original, Mode: "manifest", JournalRevision: state.Revision, StateDigest: digest}
	return r
}

func prepareNativeRemovalRecovery(ctx context.Context, originalID string, descriptor packageapi.Removal, digest string) (nativeRemoval, error) {
	return netbirdinstall.PrepareRemovalRecovery(ctx, originalID, descriptor, digest)
}

// The common executor owns the mutex through acquisition, admission, Run and
// Close. Every expensive native observation is bracketed by the same original
// release and current journal revision; only journal admission permits mutation.
func (s *DurableService) acquireRemovalRecovery(ctx context.Context, c netbirdcommand.Command) (*nativePackageLease, error) {
	p := s.removalRecovery
	if p == nil || p.inspect == nil || p.prepare == nil || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || c.Version != netbirdcommand.RemovalRecoveryVersion || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
		return nil, ErrInvalidAction
	}
	original := c.RemovalRecovery.Original
	state, err := s.journal.RemovalRecoveryState(c.Identity, original, time.Now())
	if err != nil || state.Revision != c.RemovalRecovery.JournalRevision {
		return nil, ErrActionUnconfirmed
	}
	native, err := p.prepare(ctx, original.RequestID, original.Removal, c.RemovalRecovery.StateDigest)
	if err != nil || native == nil {
		if native != nil {
			_ = native.Close()
		}
		return nil, ErrActionUnconfirmed
	}
	after, err := s.journal.RemovalRecoveryState(c.Identity, original, time.Now())
	if err != nil || after != state || ctx.Err() != nil || s.ctx.Err() != nil || !c.Executable(s.identity, time.Now()) {
		_ = native.Close()
		return nil, ErrActionUnconfirmed
	}
	return &nativePackageLease{revision: state.Revision, run: native.Run, release: native.Close}, nil
}
