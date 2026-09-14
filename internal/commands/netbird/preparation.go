package netbird

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
)

type preparedPackage interface {
	Verify(context.Context, packageapi.Package) error
	Close() error
}

// preparationOwner retains one bounded private artifact. The executor mutex
// serializes download with device commands; this mutex also joins cleanup with
// inspection. Only the service owns this state, including its immutable identity.
type preparationOwner struct {
	mu       sync.Mutex
	stage    func(context.Context, packageapi.Package) (preparedPackage, error)
	request  netbirdcommand.PreparationRequest
	prepared preparedPackage
	poisoned bool
}

// NewDurableServiceWithPreparation also owns the fixed private staging root.
// The caller must hold the supplied journal's exclusive installation lease and
// supply a sibling directory beneath the validated individual identity directory.
// Supported native package owners are configured together with their inspection
// paths. A failed creation leaves journal ownership unchanged.
func NewDurableServiceWithPreparation(parent context.Context, journal *netbirdjournal.Journal, identity netbirdcommand.Identity, expires time.Time, root string) (*DurableService, error) {
	if !identity.Individual || runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, ErrInvalidAction
	}
	s, err := NewDurableService(parent, journal, identity, expires)
	if err != nil {
		return nil, err
	}
	if netbirdinstall.ResetRoot(root) != nil {
		s.cancel()
		return nil, ErrActionUnconfirmed
	}
	s.preparation = &preparationOwner{stage: func(ctx context.Context, pkg packageapi.Package) (preparedPackage, error) {
		if netbirdinstall.CheckEmptyRoot(root) != nil {
			s.preparation.poisoned = true
			return nil, ErrActionUnconfirmed
		}
		p, err := netbirdinstall.Stage(ctx, pkg, identity.TenantID, root)
		if err != nil {
			// A failed cleanup must prevent accumulation under the same owner.
			if netbirdinstall.CheckEmptyRoot(root) != nil {
				s.preparation.poisoned = true
			}
			return nil, err
		}
		return p, nil
	}}
	s.startPreparationCleanup()
	if netbirdinstall.InstallationSupported() {
		s.installation = prepareNativeInstallation
		s.executor.install = s.acquireInstallation
	}
	if netbirdinstall.RemovalSupported() {
		s.removal = &removalOwner{inspect: netbirdinstall.InspectRemoval, prepare: prepareNativeRemoval}
		s.executor.remove = s.acquireRemoval
	}
	return s, nil
}

func (s *DurableService) startPreparationCleanup() {
	s.work.Add(1)
	go func() {
		defer s.work.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				s.preparation.mu.Lock()
				s.preparation.clearLocked()
				s.preparation.mu.Unlock()
				return
			case <-ticker.C:
				p := s.preparation
				if p.mu.TryLock() {
					if p.prepared != nil && (!p.request.ExpiresAt.After(time.Now()) || s.journal.State(time.Now()).Revision != p.request.JournalRevision) {
						p.clearLocked()
					}
					p.mu.Unlock()
				}
			}
		}
	}()
}

func (p *preparationOwner) clearLocked() {
	if p.prepared != nil && p.prepared.Close() != nil {
		p.poisoned = true
	}
	p.prepared = nil
	p.request = netbirdcommand.PreparationRequest{}
}

func (s *DurableService) preparationState(c netbirdcommand.ControlRequest) netbirdcommand.ControlResponse {
	r, _ := netbirdcommand.ControlResponseFor(c, "unavailable")
	p := s.preparation
	if p == nil || !p.mu.TryLock() {
		return r
	}
	defer p.mu.Unlock()
	if c.Kind == "installation-state" && s.installation == nil {
		return r
	}
	if p.poisoned || s.ctx.Err() != nil || !c.Executable(s.identity, time.Now()) {
		return r
	}
	r.Outcome, r.State = "ok", s.journal.State(time.Now())
	return r
}

func (s *DurableService) prepare(ctx context.Context, c netbirdcommand.PreparationRequest) netbirdcommand.PreparationResponse {
	respond := func(outcome string) netbirdcommand.PreparationResponse {
		r, _ := netbirdcommand.PreparationResponseFor(c, outcome)
		return r
	}
	p := s.preparation
	if p == nil || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
		return respond("unavailable")
	}
	ctx, stop := context.WithDeadline(ctx, c.ExpiresAt)
	defer stop()
	if !s.executor.mu.TryLock() {
		return respond("blocked")
	}
	defer s.executor.mu.Unlock()
	if !p.mu.TryLock() {
		return respond("blocked")
	}
	defer p.mu.Unlock()
	if p.poisoned {
		return respond("unavailable")
	}
	state := s.journal.State(time.Now())
	if !state.Valid() || state.Status != "ready" || state.Revision != c.JournalRevision {
		p.clearLocked()
		return respond("blocked")
	}
	if p.prepared != nil {
		if !p.request.ExpiresAt.After(time.Now()) || p.request.JournalRevision != state.Revision {
			p.clearLocked()
		} else {
			if p.request.RequestID != c.RequestID {
				return respond("blocked")
			}
			hash, _ := p.request.Digest()
			incoming, _ := c.Digest()
			if hash != incoming {
				return respond("conflict")
			}
			if p.prepared.Verify(ctx, c.Package) != nil {
				p.clearLocked()
				return respond("unavailable")
			}
			if ctx.Err() != nil || s.journal.State(time.Now()) != state {
				p.clearLocked()
				return respond("blocked")
			}
			return respond("prepared")
		}
	}
	if p.poisoned || ctx.Err() != nil {
		return respond("unavailable")
	}
	// An independent upper bound protects the service even if a preparation RPC
	// grants a longer retention window for the subsequent fresh command.
	stageCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	prepared, err := p.stage(stageCtx, c.Package)
	if err != nil || prepared == nil {
		if prepared != nil && prepared.Close() != nil {
			p.poisoned = true
		}
		return respond("unavailable")
	}
	p.prepared, p.request = prepared, c
	if stageCtx.Err() != nil || !c.Executable(s.identity, time.Now()) || s.journal.State(time.Now()) != state {
		p.clearLocked()
		return respond("blocked")
	}
	return respond("prepared")
}

func (s *DurableService) preparationHandler(subject string, binding *netbirdServiceBinding) nats.MsgHandler {
	return func(msg *nats.Msg) {
		if msg == nil {
			return
		}
		reject := func() { _ = msg.Respond([]byte("NetBird preparation is unavailable")) }
		if msg.Subject != subject || msg.Reply == "" || !s.admit(binding) {
			reject()
			return
		}
		defer s.work.Done()
		c, err := netbirdcommand.DecodePreparation(msg.Data)
		if err != nil || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
			reject()
			return
		}
		ctx, cancel := context.WithDeadline(s.ctx, c.ExpiresAt)
		defer cancel()
		r := s.prepare(ctx, c)
		data, err := netbirdcommand.EncodePreparationResponse(c, r)
		if err != nil {
			reject()
			return
		}
		_ = msg.Respond(data)
	}
}
