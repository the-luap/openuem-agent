package netbird

import (
	"context"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/netbirdinstall"
)

type nativeRemoval interface {
	Run(context.Context) error
	Close() error
}

type removalOwner struct {
	inspect func(context.Context) (packageapi.Removal, bool, error)
	prepare func(context.Context, string, packageapi.Removal) (nativeRemoval, error)
}

func (s *DurableService) removalState(ctx context.Context, c netbirdcommand.ControlRequest) netbirdcommand.ControlResponse {
	r, _ := netbirdcommand.ControlResponseFor(c, "unavailable")
	p := s.removal
	if p == nil || p.inspect == nil || p.prepare == nil || s.executor.remove == nil || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || c.Kind != "removal-state" || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
		return r
	}
	if !s.executor.mu.TryLock() {
		r.Outcome = "blocked"
		return r
	}
	defer s.executor.mu.Unlock()
	state := s.journal.State(time.Now())
	if !state.Valid() || state.Status == "unavailable" {
		return r
	}
	// Inspection remains available for explicit recovery of an unconfirmed
	// attempt. It never releases the journal or authorizes another execution.
	descriptor, absent, err := p.inspect(ctx)
	if err != nil || ctx.Err() != nil || s.ctx.Err() != nil || !c.Executable(s.identity, time.Now()) || absent && descriptor != (packageapi.Removal{}) || !absent && !descriptor.Valid() {
		return r
	}
	if s.journal.State(time.Now()) != state {
		r.Outcome = "blocked"
		return r
	}
	r.Outcome, r.State = "ok", state
	if absent {
		r.Outcome = "absent"
	} else {
		r.Removal = descriptor
	}
	return r
}

func prepareNativeRemoval(ctx context.Context, requestID string, descriptor packageapi.Removal) (nativeRemoval, error) {
	return netbirdinstall.PrepareRemoval(ctx, requestID, descriptor)
}

// The executor holds its common mutex throughout acquisition, durable admission,
// Run and Close. Preparing an owner is read-only; Run may mutate only after the
// exact reviewed command has an immutable journal attempt.
func (s *DurableService) acquireRemoval(ctx context.Context, c netbirdcommand.Command) (*nativePackageLease, error) {
	p := s.removal
	if p == nil || p.inspect == nil || p.prepare == nil || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || c.Version != netbirdcommand.RemovalVersion || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
		return nil, ErrInvalidAction
	}
	state := s.journal.State(time.Now())
	if !state.Valid() || state.Status != "ready" {
		return nil, ErrActionUnconfirmed
	}
	native, err := p.prepare(ctx, c.RequestID, c.Removal)
	if err != nil || native == nil {
		if native != nil {
			_ = native.Close()
		}
		return nil, ErrActionUnconfirmed
	}
	if ctx.Err() != nil || s.ctx.Err() != nil || !c.Executable(s.identity, time.Now()) || s.journal.State(time.Now()) != state {
		_ = native.Close()
		return nil, ErrActionUnconfirmed
	}
	return &nativePackageLease{revision: state.Revision, run: native.Run, release: native.Close}, nil
}
