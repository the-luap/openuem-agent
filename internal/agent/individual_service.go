package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/macsecurity"
	"github.com/open-uem/openuem-agent/internal/nativepath"
	"github.com/open-uem/openuem-agent/internal/service/lifecycle"
)

const individualRenewalRequestTimeout = 20 * time.Second

type individualServiceLease interface {
	io.Closer
	ValidateDirectory(string) error
}

type individualServiceStore interface {
	io.Closer
	InstallationBinding() (*enrollmentstore.InstallationBinding, error)
	RenewalSchedule() (*enrollmentstore.RenewalSchedule, error)
	Load() (*enrollmentstore.Identity, error)
	PrepareRenewal(context.Context, *x509.CertPool) (*enrollment.PreparedIdentityRenewal, error)
	ConfirmRenewal(context.Context, string, *x509.CertPool) (*enrollmentstore.Identity, error)
	ResolveRenewal(context.Context, string, *x509.CertPool) (*enrollmentstore.Identity, error)
	AbandonRenewal(string) error
}

type individualServiceDependencies struct {
	acquire func(string) (individualServiceLease, error)
	open    func(string) (individualServiceStore, error)
	verify  func(context.Context, enrollmentstore.InstallationBinding) error
	runtime func(context.Context, string, individualServiceLease, enrollmentstore.InstallationBinding) (lifecycle.Runtime, error)
	exclude func(string, string) (io.Closer, error)
	now     func() time.Time
	wait    func(context.Context, time.Duration) bool
	jitter  func(time.Duration) time.Duration
}

// NewServiceRuntime preserves explicit service configuration over environment
// selection. Individual installations have one owner across every generation;
// legacy installations retain their existing lifecycle.
func NewServiceRuntime(ctx context.Context, directory string) (lifecycle.Runtime, error) {
	if directory != "" && !nativepath.Valid(directory) {
		return nil, errIndividualAgent
	}
	mode := "true"
	if directory == "" {
		mode, directory = os.Getenv("OPENUEM_INDIVIDUAL_AGENT_MODE"), os.Getenv("OPENUEM_AGENT_IDENTITY_DIRECTORY")
	}
	return newServiceRuntime(ctx, mode, directory, New, func(ctx context.Context, directory string) (lifecycle.Runtime, error) {
		s, err := newIndividualService(ctx, directory, nativeIndividualServiceDependencies())
		if err != nil {
			return nil, err
		}
		return s, nil
	})
}

func newServiceRuntime(ctx context.Context, mode, directory string, legacy func(context.Context) (*Agent, error), individual func(context.Context, string) (lifecycle.Runtime, error)) (lifecycle.Runtime, error) {
	if ctx == nil {
		return nil, errIndividualAgent
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory, err := individualDirectory(mode, directory)
	if err != nil {
		return nil, err
	}
	if directory == "" {
		a, err := legacy(ctx)
		if err != nil {
			return nil, err
		}
		return a, nil
	}
	if !nativepath.Valid(directory) {
		return nil, errIndividualAgent
	}
	return individual(ctx, directory)
}

func nativeIndividualServiceDependencies() individualServiceDependencies {
	return individualServiceDependencies{
		acquire: func(directory string) (individualServiceLease, error) {
			return enrollmentstore.AcquireServiceLease(directory)
		},
		open: func(directory string) (individualServiceStore, error) {
			s, err := enrollmentstore.Open(directory)
			if err != nil {
				return nil, err
			}
			return s, nil
		},
		verify: verifyIndividualInstallation,
		runtime: func(ctx context.Context, directory string, lease individualServiceLease, binding enrollmentstore.InstallationBinding) (lifecycle.Runtime, error) {
			a, err := newAgentWithLease(ctx, "true", directory, lease)
			if err != nil {
				return nil, err
			}
			if a.individual == nil || !binding.Matches(a.individual.identity) {
				a.Stop()
				return nil, errIndividualAgent
			}
			return a, nil
		},
		exclude: func(directory, platform string) (io.Closer, error) {
			if platform == "macos" {
				return macsecurity.AcquireFileVaultLease(directory)
			}
			return nil, nil
		},
		now:    time.Now,
		wait:   waitIndividualService,
		jitter: func(delay time.Duration) time.Duration { return delay + time.Duration(rand.Int64N(int64(delay/4)+1)) },
	}
}

// The supervisor, rather than an Agent task, owns the generation loop. Agent.Stop
// joins every key user and OS task before handoff; starting a replacement never
// mutates keys or recipient state inside a running Agent. The service lease is
// borrowed by each Agent and held through the supervisor's final joined cleanup.
type individualService struct {
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex // serializes Start/Stop; the loop exclusively owns active after Start
	stopOnce     sync.Once
	started      bool
	done         chan struct{}
	directory    string
	deps         individualServiceDependencies
	lease        individualServiceLease
	store        individualServiceStore
	binding      enrollmentstore.InstallationBinding
	active       lifecycle.Runtime
	activeCancel context.CancelFunc
	expiresAt    time.Time
}

func newIndividualService(ctx context.Context, directory string, deps individualServiceDependencies) (_ *individualService, err error) {
	if ctx == nil || !nativepath.Valid(directory) {
		return nil, errIndividualAgent
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := &individualService{directory: directory, deps: deps}
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer func() {
		if err != nil {
			s.Stop()
		}
	}()
	s.lease, err = deps.acquire(directory)
	if err != nil {
		return nil, errIndividualAgent
	}
	if s.lease == nil || s.lease.ValidateDirectory(directory) != nil {
		return nil, errIndividualAgent
	}
	s.store, err = deps.open(directory)
	if err != nil || s.store == nil {
		return nil, errIndividualAgent
	}
	binding, err := s.store.InstallationBinding()
	if err != nil || binding == nil {
		return nil, errIndividualAgent
	}
	s.binding = *binding
	if err := s.preflight(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *individualService) preflight() error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.lease.ValidateDirectory(s.directory) != nil {
		return errIndividualAgent
	}
	binding, err := s.store.InstallationBinding()
	if err != nil || binding == nil || *binding != s.binding {
		return errIndividualAgent
	}
	if err := s.deps.verify(s.ctx, *binding); err != nil {
		return errIndividualAgent
	}
	return nil
}

func (s *individualService) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errIndividualAgent
	}
	s.started = true
	backoff := time.Minute
	for {
		if err := s.preflight(); err != nil {
			return err
		}
		schedule, err := s.store.RenewalSchedule()
		if err != nil || schedule == nil {
			return errIndividualAgent
		}
		if schedule.Pending == nil || schedule.Pending.Stage != "confirming" {
			break
		}
		if err := s.handoff(schedule.Pending.RequestID); err == nil {
			break
		}
		// Startup quarantine has no Agent/readiness endpoint. Keep service startup
		// pending and retry with bounded requests until recovery or cancellation.
		log.Print("[WARN]: individual identity recovery is pending")
		if !s.deps.wait(s.ctx, s.deps.jitter(backoff)) {
			return s.ctx.Err()
		}
		backoff = min(backoff*2, time.Hour)
	}
	if err := s.startActive(); err != nil {
		return err
	}
	s.done = make(chan struct{})
	go func() { defer close(s.done); defer s.stopActive(); s.run() }()
	return nil
}

func (s *individualService) startActive() error {
	if s.active != nil {
		return nil
	}
	if err := s.preflight(); err != nil {
		return err
	}
	i, err := s.store.Load()
	if err != nil {
		if i != nil {
			i.Close()
		}
		return errIndividualAgent
	}
	if i == nil {
		return errIndividualAgent
	}
	expires := i.Response.ExpiresAt
	valid := s.binding.Matches(i) && expires.After(s.deps.now())
	i.Close()
	if !valid {
		return errIndividualAgent
	}
	// Even if a renewal request stalls, existing task/transport contexts expire
	// at this generation's certificate deadline. The loop joins the runtime.
	ctx, cancel := context.WithDeadline(s.ctx, expires)
	runtime, err := s.deps.runtime(ctx, s.directory, s.lease, s.binding)
	if err == nil && runtime != nil {
		err = runtime.Start()
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil || runtime == nil {
		cancel()
		if runtime != nil {
			runtime.Stop()
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		return errIndividualAgent
	}
	s.active, s.activeCancel, s.expiresAt = runtime, cancel, expires
	return nil
}

func (s *individualService) stopActive() {
	if s.activeCancel != nil {
		s.activeCancel()
	}
	if s.active != nil {
		s.active.Stop()
	}
	s.active, s.activeCancel, s.expiresAt = nil, nil, time.Time{}
}

func (s *individualService) Stop() {
	s.stopOnce.Do(func() {
		s.cancel()
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.done != nil {
			<-s.done
		}
		s.stopActive()
		if s.store != nil {
			_ = s.store.Close()
		}
		if s.lease != nil {
			_ = s.lease.Close()
		}
	})
}

func (s *individualService) run() {
	backoff := time.Minute
	for s.ctx.Err() == nil {
		err := s.cycle()
		delay := time.Hour
		if err != nil {
			log.Print("[WARN]: individual identity renewal will retry")
			delay, backoff = backoff, min(backoff*2, time.Hour)
		} else {
			backoff = time.Minute
		}
		delay = s.deps.jitter(delay)
		if s.active != nil {
			delay = min(delay, max(0, s.expiresAt.Sub(s.deps.now())))
		}
		if !s.deps.wait(s.ctx, delay) {
			return
		}
	}
}

func (s *individualService) cycle() error {
	if err := s.preflight(); err != nil {
		s.stopActive()
		return err
	}
	schedule, err := s.store.RenewalSchedule()
	if err != nil || schedule == nil {
		s.stopActive()
		return errIndividualAgent
	}
	pending := schedule.Pending
	if pending != nil && pending.Stage == "confirming" {
		s.stopActive()
		if err := s.handoff(pending.RequestID); err != nil {
			return err
		}
		return s.startActive()
	}
	if s.active != nil && !s.expiresAt.After(s.deps.now()) {
		s.stopActive()
	}
	if err := s.startActive(); err != nil {
		return err
	}
	if pending == nil && (schedule.ExpiresAt.After(s.deps.now().Add(30*24*time.Hour)) || schedule.RetryAfter.After(s.deps.now())) {
		return nil
	}
	if pending != nil {
		expired := pending.Stage == "prepared" && !pending.ExpiresAt.After(s.deps.now())
		// A candidate without issuance never authorized confirmation. Retiring
		// one after seven days also recovers a permanently lost preparation reply;
		// the registry still enforces any surviving server reservation.
		aged := pending.Stage == "candidate" && !pending.CreatedAt.IsZero() && !pending.CreatedAt.Add(7*24*time.Hour).After(s.deps.now())
		if expired || aged {
			if err := s.store.AbandonRenewal(pending.RequestID); err != nil {
				s.stopActive()
				return err
			}
		}
	}
	ctx, cancel := context.WithDeadline(s.ctx, minTime(s.expiresAt, s.deps.now().Add(individualRenewalRequestTimeout)))
	prepared, err := s.store.PrepareRenewal(ctx, nil)
	cancel()
	if err != nil {
		if errors.Is(err, enrollmentstore.ErrRenewalHandoff) {
			s.stopActive()
		}
		if errors.Is(err, enrollment.ErrIdentityRenewalNotDue) {
			return nil
		}
		return err
	}
	if prepared == nil {
		return errIndividualAgent
	}
	s.stopActive()
	if err := s.handoff(prepared.ID); err != nil {
		return err
	}
	return s.startActive()
}

func (s *individualService) handoff(requestID string) error {
	if s.active != nil {
		return errIndividualAgent
	}
	if err := s.preflight(); err != nil {
		return err
	}
	exclusion, err := s.deps.exclude(s.directory, s.binding.Platform)
	if err != nil {
		return errIndividualAgent
	}
	if exclusion != nil {
		defer exclusion.Close()
	}
	if err := s.preflight(); err != nil {
		return err
	}
	// FileVault exclusion alone does not prove an orphaned mutation stopped.
	// Existing durable task/receipt guards remain authoritative at the registry.
	ctx, cancel := context.WithTimeout(s.ctx, individualRenewalRequestTimeout)
	i, err := s.store.ConfirmRenewal(ctx, requestID, nil)
	cancel()
	if i != nil {
		i.Close()
	}
	if err == nil {
		return nil
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if err := s.preflight(); err != nil {
		return err
	}
	ctx, cancel = context.WithTimeout(s.ctx, individualRenewalRequestTimeout)
	defer cancel()
	i, err = s.store.ResolveRenewal(ctx, requestID, nil)
	if i != nil {
		i.Close()
	}
	return err
}

func waitIndividualService(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
