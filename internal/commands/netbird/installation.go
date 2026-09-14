package netbird

import (
	"context"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/netbirdinstall"
)

type nativeInstallation interface {
	Run(context.Context) error
	Close() error
}

type installationPlanner func(context.Context, preparedPackage, packageapi.Package) (nativeInstallation, error)

func prepareNativeInstallation(ctx context.Context, artifact preparedPackage, descriptor packageapi.Package) (nativeInstallation, error) {
	prepared, ok := artifact.(*netbirdinstall.Prepared)
	if !ok {
		return nil, ErrInvalidAction
	}
	return prepared.PrepareInstallation(ctx, descriptor)
}

// acquireInstallation is called with the executor mutex held. Ownership of the
// preparation mutex and native plan transfers to the returned lease, excluding
// expiry cleanup and another command until the native process and cleanup join.
func (s *DurableService) acquireInstallation(ctx context.Context, c netbirdcommand.Command) (*nativePackageLease, error) {
	p := s.preparation
	if p == nil || s.installation == nil || ctx == nil || ctx.Err() != nil || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
		return nil, ErrInvalidAction
	}
	if !p.mu.TryLock() {
		return nil, ErrActionUnconfirmed
	}
	transferred := false
	defer func() {
		if !transferred {
			p.mu.Unlock()
		}
	}()
	if p.poisoned || p.prepared == nil || !p.request.Executable(s.identity, time.Now()) || p.request.RequestID != c.RequestID || p.request.Revision != c.Revision || p.request.Package != c.Package || c.IssuedAt.Before(p.request.IssuedAt) {
		return nil, ErrInvalidAction
	}
	state := s.journal.State(time.Now())
	if state.Status != "ready" || state.Revision != p.request.JournalRevision {
		p.clearLocked()
		return nil, ErrActionUnconfirmed
	}
	native, err := s.installation(ctx, p.prepared, c.Package)
	if err != nil || native == nil {
		if native != nil {
			_ = native.Close()
		}
		p.clearLocked()
		return nil, ErrActionUnconfirmed
	}
	if ctx.Err() != nil || !p.request.Executable(s.identity, time.Now()) || s.journal.State(time.Now()) != state {
		_ = native.Close()
		p.clearLocked()
		return nil, ErrActionUnconfirmed
	}
	transferred = true
	return &nativePackageLease{revision: state.Revision, run: native.Run, release: func() error {
		defer p.mu.Unlock()
		err := native.Close()
		p.clearLocked()
		if p.poisoned || err != nil {
			return ErrActionUnconfirmed
		}
		return nil
	}}, nil
}
