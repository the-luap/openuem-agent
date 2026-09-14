package netbird

import (
	"context"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-agent/internal/netbirdinstall"
)

type removalAbsenceOwner struct {
	inspect func(context.Context) (string, error)
	prepare func(context.Context, string) (nativeRemoval, error)
}

func (s *DurableService) removalAbsenceState(ctx context.Context, c netbirdcommand.ControlRequest) netbirdcommand.ControlResponse {
	r, _ := netbirdcommand.ControlResponseFor(c, "unavailable")
	p := s.removalAbsence
	if p == nil || p.inspect == nil || p.prepare == nil || s.executor.verifyRemovalAbsence == nil || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || c.Version != netbirdcommand.RemovalAbsenceInspectionVersion || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
		return r
	}
	if !s.executor.mu.TryLock() {
		r.Outcome = "blocked"
		return r
	}
	defer s.executor.mu.Unlock()
	original := c.RemovalAbsenceOriginal
	state, err := s.journal.RemovalAbsenceState(c.Identity, original, time.Now())
	if err != nil {
		r.Outcome = recoveryJournalOutcome(err)
		return r
	}
	digest, err := p.inspect(ctx)
	if err != nil || !netbirdcommand.ValidDigest(digest) || ctx.Err() != nil || s.ctx.Err() != nil || !c.Executable(s.identity, time.Now()) {
		return r
	}
	after, err := s.journal.RemovalAbsenceState(c.Identity, original, time.Now())
	if err != nil {
		r.Outcome = recoveryJournalOutcome(err)
		return r
	}
	if after != state {
		r.Outcome = "blocked"
		return r
	}
	r.Outcome, r.State = "ok", state
	r.RemovalAbsence = netbirdcommand.RemovalAbsence{Original: original, Profile: netbirdcommand.RemovalAbsenceProfile, JournalRevision: state.Revision, StateDigest: digest}
	return r
}

func prepareNativeRemovalAbsence(ctx context.Context, digest string) (nativeRemoval, error) {
	return netbirdinstall.PrepareRemovalAbsence(ctx, digest)
}

// The common executor owns the mutex through acquisition, admission, Run and
// Close. Every expensive native observation is bracketed by the same original
// release and current journal revision. Journal admission records this separate
// current-state verification.
func (s *DurableService) acquireRemovalAbsence(ctx context.Context, c netbirdcommand.Command) (*nativePackageLease, error) {
	p := s.removalAbsence
	if p == nil || p.inspect == nil || p.prepare == nil || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || c.Version != netbirdcommand.RemovalAbsenceVersion || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
		return nil, ErrInvalidAction
	}
	original := c.RemovalAbsence.Original
	state, err := s.journal.RemovalAbsenceState(c.Identity, original, time.Now())
	if err != nil || state.Revision != c.RemovalAbsence.JournalRevision {
		return nil, ErrActionUnconfirmed
	}
	native, err := p.prepare(ctx, c.RemovalAbsence.StateDigest)
	if err != nil || native == nil {
		if native != nil {
			_ = native.Close()
		}
		return nil, ErrActionUnconfirmed
	}
	after, err := s.journal.RemovalAbsenceState(c.Identity, original, time.Now())
	if err != nil || after != state || ctx.Err() != nil || s.ctx.Err() != nil || !c.Executable(s.identity, time.Now()) {
		_ = native.Close()
		return nil, ErrActionUnconfirmed
	}
	return &nativePackageLease{revision: state.Revision, run: native.Run, release: native.Close}, nil
}
