package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/service/lifecycle"
)

type serviceStoreFixture struct {
	binding          func() (*enrollmentstore.InstallationBinding, error)
	schedule         func() (*enrollmentstore.RenewalSchedule, error)
	load             func() (*enrollmentstore.Identity, error)
	prepare          func(context.Context) (*enrollment.PreparedIdentityRenewal, error)
	confirm, resolve func(context.Context, string) (*enrollmentstore.Identity, error)
	abandon          func(string) error
	close            func() error
}

func (s *serviceStoreFixture) InstallationBinding() (*enrollmentstore.InstallationBinding, error) {
	return s.binding()
}
func (s *serviceStoreFixture) RenewalSchedule() (*enrollmentstore.RenewalSchedule, error) {
	return s.schedule()
}
func (s *serviceStoreFixture) Load() (*enrollmentstore.Identity, error) { return s.load() }
func (s *serviceStoreFixture) PrepareRenewal(ctx context.Context, roots *x509.CertPool) (*enrollment.PreparedIdentityRenewal, error) {
	if roots != nil {
		panic("service replaced system HTTPS trust")
	}
	return s.prepare(ctx)
}
func (s *serviceStoreFixture) ConfirmRenewal(ctx context.Context, id string, roots *x509.CertPool) (*enrollmentstore.Identity, error) {
	if roots != nil {
		panic("service replaced system HTTPS trust")
	}
	return s.confirm(ctx, id)
}
func (s *serviceStoreFixture) ResolveRenewal(ctx context.Context, id string, roots *x509.CertPool) (*enrollmentstore.Identity, error) {
	if roots != nil {
		panic("service replaced system HTTPS trust")
	}
	return s.resolve(ctx, id)
}
func (s *serviceStoreFixture) AbandonRenewal(id string) error { return s.abandon(id) }
func (s *serviceStoreFixture) Close() error                   { return s.close() }

type serviceLeaseFixture struct {
	validate func(string) error
	close    func() error
}

func (l *serviceLeaseFixture) ValidateDirectory(directory string) error { return l.validate(directory) }
func (l *serviceLeaseFixture) Close() error                             { return l.close() }

type serviceCloserFixture func() error

func (c serviceCloserFixture) Close() error { return c() }

type serviceRuntimeFixture struct {
	start func() error
	stop  func()
}

func (r *serviceRuntimeFixture) Start() error { return r.start() }
func (r *serviceRuntimeFixture) Stop()        { r.stop() }

type serviceWaitFixture struct {
	delay  time.Duration
	resume chan struct{}
}

type individualServiceFixture struct {
	t                                                           *testing.T
	mu                                                          sync.Mutex
	directory                                                   string
	events                                                      []string
	binding                                                     enrollmentstore.InstallationBinding
	now, expires, retryAfter                                    time.Time
	pending                                                     *enrollmentstore.RenewalStatus
	generation                                                  string
	active                                                      int
	held, excluded, invalidLease, invalidImage, corrupt, closed bool
	identities                                                  []*enrollmentstore.Identity
	stopGate                                                    <-chan struct{}
	waits                                                       chan serviceWaitFixture
	store                                                       *serviceStoreFixture
	deps                                                        individualServiceDependencies
}

func newIndividualServiceFixture(t *testing.T) *individualServiceFixture {
	t.Helper()
	f := &individualServiceFixture{t: t, directory: t.TempDir(), now: time.Now(), generation: "old", waits: make(chan serviceWaitFixture, 1)}
	f.expires = f.now.Add(25 * 24 * time.Hour)
	f.binding = enrollmentstore.InstallationBinding{DeviceID: individualFixtureID, TenantID: 3, SiteID: 4, Origin: "https://fixture.invalid", Platform: "macos", Architecture: "arm64", ReleaseDigest: "fixture-release", ReleaseSequence: 42, AgentSize: 1234, AgentSHA256: "fixture-image"}
	f.store = &serviceStoreFixture{
		binding: func() (*enrollmentstore.InstallationBinding, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, "binding")
			if f.corrupt || f.closed {
				return nil, enrollmentstore.ErrUnavailable
			}
			b := f.binding
			return &b, nil
		},
		schedule: func() (*enrollmentstore.RenewalSchedule, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			result := &enrollmentstore.RenewalSchedule{ExpiresAt: f.expires, RetryAfter: f.retryAfter}
			if f.pending != nil {
				p := *f.pending
				result.Pending = &p
			}
			return result, nil
		},
		load: func() (*enrollmentstore.Identity, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, "load")
			if f.pending != nil && f.pending.Stage == "confirming" {
				return nil, enrollmentstore.ErrRenewalHandoff
			}
			if !f.expires.After(f.now) {
				return nil, enrollmentstore.ErrUnavailable
			}
			return f.identityLocked(), nil
		},
		prepare: func(ctx context.Context) (*enrollment.PreparedIdentityRenewal, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.checkRequestLocked(ctx, false)
			f.events = append(f.events, "prepare")
			f.pending = &enrollmentstore.RenewalStatus{RequestID: individualFixtureID, Stage: "prepared", CreatedAt: f.now, ExpiresAt: f.now.Add(7 * 24 * time.Hour)}
			return &enrollment.PreparedIdentityRenewal{ID: individualFixtureID}, nil
		},
		confirm: func(ctx context.Context, id string) (*enrollmentstore.Identity, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.checkRequestLocked(ctx, true)
			f.events = append(f.events, "confirm")
			if id != individualFixtureID {
				t.Error("confirmation selected another candidate")
			}
			f.pending, f.generation, f.expires = nil, "new", f.now.Add(90*24*time.Hour)
			return f.identityLocked(), nil
		},
		resolve: func(ctx context.Context, id string) (*enrollmentstore.Identity, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.checkRequestLocked(ctx, true)
			f.events = append(f.events, "resolve")
			if id != individualFixtureID {
				t.Error("resolution selected another candidate")
			}
			f.pending = nil
			f.retryAfter = f.now.Add(7 * 24 * time.Hour)
			return f.identityLocked(), nil
		},
		abandon: func(id string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, "abandon")
			if f.pending == nil || f.pending.Stage == "confirming" || id != f.pending.RequestID {
				t.Error("unsafe abandonment")
			}
			f.pending = nil
			return nil
		},
		close: func() error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if !f.held || f.active != 0 || f.excluded {
				t.Error("store closed before quiescence")
			}
			f.closed = true
			f.events = append(f.events, "store-close")
			return nil
		},
	}
	f.deps = individualServiceDependencies{
		acquire: func(directory string) (individualServiceLease, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if directory != f.directory || f.held {
				return nil, enrollmentstore.ErrServiceBusy
			}
			f.held = true
			f.events = append(f.events, "acquire")
			return &serviceLeaseFixture{
				validate: func(directory string) error {
					f.mu.Lock()
					defer f.mu.Unlock()
					if !f.held || f.invalidLease || directory != f.directory {
						return enrollmentstore.ErrUnavailable
					}
					return nil
				},
				close: func() error {
					f.mu.Lock()
					defer f.mu.Unlock()
					if f.active != 0 || f.excluded {
						t.Error("lease closed with live users")
					}
					f.held = false
					f.events = append(f.events, "lease-close")
					return nil
				},
			}, nil
		},
		open: func(string) (individualServiceStore, error) { return f.store, nil },
		verify: func(ctx context.Context, binding enrollmentstore.InstallationBinding) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, "verify")
			if ctx.Err() != nil || f.invalidImage || !f.held || binding != f.binding {
				return errIndividualAgent
			}
			return nil
		},
		runtime: func(ctx context.Context, directory string, lease individualServiceLease, binding enrollmentstore.InstallationBinding) (lifecycle.Runtime, error) {
			f.mu.Lock()
			f.events = append(f.events, "construct-"+f.generation)
			f.mu.Unlock()
			if directory != f.directory || lease.ValidateDirectory(directory) != nil {
				return nil, errIndividualAgent
			}
			started := false
			return &serviceRuntimeFixture{
				start: func() error {
					f.mu.Lock()
					defer f.mu.Unlock()
					if ctx.Err() != nil || f.active != 0 || !f.held || f.excluded || binding != f.binding {
						t.Error("replacement overlapped key users or lost ownership")
					}
					started = true
					f.active++
					f.events = append(f.events, "start-"+f.generation)
					return nil
				},
				stop: func() {
					f.mu.Lock()
					f.events = append(f.events, "stop-begin")
					gate := f.stopGate
					f.mu.Unlock()
					if gate != nil {
						<-gate
					}
					f.mu.Lock()
					defer f.mu.Unlock()
					if ctx.Err() == nil {
						t.Error("runtime stop preceded cancellation")
					}
					if started {
						f.active--
						started = false
					}
					f.events = append(f.events, "stop-end")
				},
			}, nil
		},
		exclude: func(string, string) (io.Closer, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.active != 0 || !f.held || f.excluded {
				t.Error("handoff exclusion preceded joined shutdown")
			}
			f.excluded = true
			f.events = append(f.events, "exclude")
			return serviceCloserFixture(func() error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.excluded = false
				f.events = append(f.events, "exclude-close")
				return nil
			}), nil
		},
		now: func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now },
		wait: func(ctx context.Context, delay time.Duration) bool {
			w := serviceWaitFixture{delay: delay, resume: make(chan struct{})}
			select {
			case f.waits <- w:
			case <-ctx.Done():
				return false
			}
			select {
			case <-w.resume:
				return ctx.Err() == nil
			case <-ctx.Done():
				return false
			}
		},
		jitter: func(delay time.Duration) time.Duration { return delay },
	}
	return f
}

func (f *individualServiceFixture) identityLocked() *enrollmentstore.Identity {
	key, err := nkeys.CreateUser()
	if err != nil {
		f.t.Fatal(err)
	}
	b := f.binding
	i := &enrollmentstore.Identity{Keys: &enrollment.Keys{Broker: key}, Response: enrollment.Response{DeviceID: b.DeviceID, TenantID: b.TenantID, SiteID: b.SiteID, Certificate: f.generation, ExpiresAt: f.expires}, Origin: b.Origin, Platform: b.Platform, Architecture: b.Architecture, ReleaseDigest: b.ReleaseDigest, ReleaseSequence: b.ReleaseSequence, AgentSize: b.AgentSize, AgentSHA256: b.AgentSHA256}
	f.identities = append(f.identities, i)
	return i
}

func (f *individualServiceFixture) checkRequestLocked(ctx context.Context, quiescent bool) {
	f.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > individualRenewalRequestTimeout+time.Second || ctx.Err() != nil || !f.held {
		f.t.Error("request escaped deadline or service ownership")
	}
	if quiescent && (f.active != 0 || !f.excluded) {
		f.t.Error("handoff overlapped old key/OS users")
	}
	if !quiescent && f.active != 1 {
		f.t.Error("preparation stopped the working generation")
	}
}

func (f *individualServiceFixture) service() *individualService {
	f.t.Helper()
	s, err := newIndividualService(f.t.Context(), f.directory, f.deps)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(s.Stop)
	return s
}

func (f *individualServiceFixture) eventsCopy() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.events)
}
func (f *individualServiceFixture) nextWait() serviceWaitFixture {
	f.t.Helper()
	select {
	case w := <-f.waits:
		return w
	case <-time.After(10 * time.Second):
		f.t.Fatal("service did not reach a bounded wait")
		return serviceWaitFixture{}
	}
}
func assertServiceOrder(t *testing.T, events []string, want ...string) {
	t.Helper()
	at := 0
	for _, event := range want {
		index := slices.Index(events[at:], event)
		if index < 0 {
			t.Fatalf("missing ordered event %q in %v", event, events)
		}
		at += index + 1
	}
}

func TestIndividualServiceRenewsOnlyAfterEveryOldUserJoins(t *testing.T) {
	f := newIndividualServiceFixture(t)
	gate := make(chan struct{})
	f.stopGate = gate
	s := f.service()
	if err := s.startActive(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- s.cycle() }()
	deadline := time.After(5 * time.Second)
	for !slices.Contains(f.eventsCopy(), "stop-begin") {
		select {
		case <-deadline:
			t.Fatal("old runtime did not stop")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if events := f.eventsCopy(); slices.Contains(events, "confirm") || slices.Contains(events, "exclude") || slices.Contains(events, "start-new") {
		t.Fatal("handoff did not join old tasks", events)
	}
	close(gate)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	s.Stop()
	assertServiceOrder(t, f.eventsCopy(), "acquire", "verify", "load", "start-old", "prepare", "stop-begin", "stop-end", "exclude", "confirm", "exclude-close", "load", "start-new", "stop-end", "store-close", "lease-close")
	for _, identity := range f.identities {
		if identity.Keys != nil {
			t.Fatal("supervisor retained an unused decoded identity")
		}
	}
}

func TestIndividualServiceLostConfirmationUsesOnlyDurableResolution(t *testing.T) {
	for _, outcome := range []string{"confirmed", "cancelled", "unknown"} {
		t.Run(outcome, func(t *testing.T) {
			f := newIndividualServiceFixture(t)
			f.store.confirm = func(ctx context.Context, _ string) (*enrollmentstore.Identity, error) {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.checkRequestLocked(ctx, true)
				f.events = append(f.events, "confirm-lost")
				f.pending.Stage = "confirming"
				return nil, enrollment.ErrEnrollmentBusy
			}
			resolve := f.store.resolve
			f.store.resolve = func(ctx context.Context, id string) (*enrollmentstore.Identity, error) {
				if outcome == "unknown" {
					f.mu.Lock()
					defer f.mu.Unlock()
					f.checkRequestLocked(ctx, true)
					f.events = append(f.events, "resolve-lost")
					return nil, enrollment.ErrEnrollmentBusy
				}
				if outcome == "confirmed" {
					f.mu.Lock()
					f.generation, f.expires = "new", f.now.Add(90*24*time.Hour)
					f.mu.Unlock()
				}
				return resolve(ctx, id)
			}
			s := f.service()
			if err := s.startActive(); err != nil {
				t.Fatal(err)
			}
			err := s.cycle()
			if outcome == "unknown" {
				if err == nil || s.active != nil || f.pending == nil || f.pending.Stage != "confirming" {
					t.Fatal("ambiguous response restored source credentials")
				}
				if err := s.cycle(); err == nil || s.active != nil {
					t.Fatal("retry escaped quarantine")
				}
				if count := slices.Collect(func(yield func(string) bool) {
					for _, event := range f.eventsCopy() {
						if event == "start-old" {
							yield(event)
						}
					}
				}); len(count) != 1 {
					t.Fatal("old runtime was recreated during quarantine")
				}
			} else {
				if err != nil || s.active == nil {
					t.Fatal("durable resolution did not restart selected identity", err)
				}
				want := "start-old"
				if outcome == "confirmed" {
					want = "start-new"
				}
				assertServiceOrder(t, f.eventsCopy(), "start-old", "stop-end", "confirm-lost", "resolve", "exclude-close", "load", want)
				before := f.eventsCopy()
				if err := s.cycle(); err != nil {
					t.Fatal(err)
				}
				if slices.Contains(f.eventsCopy()[len(before):], "prepare") {
					t.Fatal("renewed/cancelled generation ignored its due time/cooldown")
				}
			}
		})
	}
}

func TestIndividualServiceStartupRecoveryRemainsPendingAndStopCancelsIt(t *testing.T) {
	f := newIndividualServiceFixture(t)
	f.pending = &enrollmentstore.RenewalStatus{RequestID: individualFixtureID, Stage: "confirming"}
	f.store.confirm = func(ctx context.Context, _ string) (*enrollmentstore.Identity, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.checkRequestLocked(ctx, true)
		f.events = append(f.events, "confirm-lost")
		return nil, enrollment.ErrEnrollmentBusy
	}
	f.store.resolve = func(ctx context.Context, _ string) (*enrollmentstore.Identity, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.checkRequestLocked(ctx, true)
		return nil, enrollment.ErrEnrollmentBusy
	}
	s := f.service()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	for _, delay := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		w := f.nextWait()
		if w.delay != delay {
			t.Fatal("startup recovery did not back off", w.delay)
		}
		select {
		case <-s.Ready():
			t.Fatal("unresolved startup reported agent readiness")
		default:
		}
		if slices.Contains(f.eventsCopy(), "load") {
			t.Fatal("startup quarantine released old keys")
		}
		close(w.resume)
	}
	_ = f.nextWait()
	s.Stop()
	select {
	case <-s.Ready():
		t.Fatal("shutdown granted readiness to unresolved identity")
	default:
	}
	if f.held || !f.closed {
		t.Fatal("pending startup leaked native resources")
	}
}

func TestIndividualServiceStartupRecoversActivatedCandidateAfterSourceExpiry(t *testing.T) {
	f := newIndividualServiceFixture(t)
	f.pending = &enrollmentstore.RenewalStatus{RequestID: individualFixtureID, Stage: "confirming"}
	f.expires = f.now.Add(-time.Hour)
	s := f.service()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	_ = f.nextWait()
	select {
	case <-s.Ready():
	default:
		t.Fatal("recovered generation did not announce readiness")
	}
	s.Stop()
	assertServiceOrder(t, f.eventsCopy(), "verify", "exclude", "confirm", "exclude-close", "load", "start-new")
	if slices.Contains(f.eventsCopy(), "start-old") {
		t.Fatal("expired source was started")
	}
}

func TestIndividualServiceShutdownJoinsInFlightRenewalWithoutResolvingAfterCancellation(t *testing.T) {
	f := newIndividualServiceFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.store.confirm = func(ctx context.Context, _ string) (*enrollmentstore.Identity, error) {
		f.mu.Lock()
		f.checkRequestLocked(ctx, true)
		f.pending.Stage = "confirming"
		f.mu.Unlock()
		close(entered)
		<-ctx.Done()
		<-release
		return nil, ctx.Err()
	}
	s := f.service()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	<-entered
	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("service released store before renewal request joined")
	case <-time.After(20 * time.Millisecond):
	}
	f.mu.Lock()
	held, closed := f.held, f.closed
	f.mu.Unlock()
	if !held || closed {
		t.Fatal("shutdown lost ownership while exchange was live")
	}
	close(release)
	<-stopped
	if slices.Contains(f.eventsCopy(), "resolve") || f.pending.Stage != "confirming" {
		t.Fatal("shutdown resolved or discarded ambiguous confirmation")
	}
}

func TestIndividualServiceInvalidLocalStateStopsBeforeNetworkOrReplacement(t *testing.T) {
	for _, failure := range []string{"lease", "image", "history", "binding"} {
		t.Run(failure, func(t *testing.T) {
			f := newIndividualServiceFixture(t)
			s := f.service()
			if err := s.startActive(); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "lease":
				f.invalidLease = true
			case "image":
				f.invalidImage = true
			case "history":
				f.corrupt = true
			case "binding":
				f.binding.SiteID++
			}
			if err := s.cycle(); err == nil || s.active != nil {
				t.Fatal("invalid installation retained a working identity")
			}
			if events := f.eventsCopy(); slices.Contains(events, "prepare") || slices.Contains(events, "confirm") || slices.Contains(events, "resolve") {
				t.Fatal("unverified installation made renewal requests", events)
			}
		})
	}
}

func TestIndividualServiceExpiredPreparationCanRetireButConfirmationCannot(t *testing.T) {
	for _, stage := range []string{"candidate", "prepared", "confirming"} {
		t.Run(stage, func(t *testing.T) {
			f := newIndividualServiceFixture(t)
			f.pending = &enrollmentstore.RenewalStatus{RequestID: individualFixtureID, Stage: stage, CreatedAt: f.now.Add(-8 * 24 * time.Hour), ExpiresAt: f.now.Add(-time.Hour)}
			s := f.service()
			if stage != "confirming" {
				if err := s.startActive(); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.cycle(); err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(f.eventsCopy(), "abandon"); got != (stage != "confirming") {
				t.Fatal("attempt retirement did not respect durable confirmation intent")
			}
		})
	}
}

func TestIndividualServicePreparationFailureKeepsWorkingGenerationAndBacksOff(t *testing.T) {
	f := newIndividualServiceFixture(t)
	f.store.prepare = func(ctx context.Context) (*enrollment.PreparedIdentityRenewal, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.checkRequestLocked(ctx, false)
		return nil, enrollment.ErrEnrollmentBusy
	}
	s := f.service()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	for _, delay := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour} {
		w := f.nextWait()
		if w.delay != delay {
			t.Fatal("retry was not capped exponential backoff", w.delay)
		}
		f.mu.Lock()
		active := f.active
		f.mu.Unlock()
		if active != 1 {
			t.Fatal("preparation failure stopped usable source")
		}
		close(w.resume)
	}
	_ = f.nextWait()
	s.Stop()
}

func TestIndividualServiceExpiryStopsInsteadOfResumingExpiredSource(t *testing.T) {
	f := newIndividualServiceFixture(t)
	s := f.service()
	if err := s.startActive(); err != nil {
		t.Fatal(err)
	}
	f.now = f.expires
	if err := s.cycle(); err == nil || s.active != nil || slices.Contains(f.eventsCopy(), "prepare") {
		t.Fatal("expired source remained active or reached preparation")
	}
}

func TestIndividualServiceFactoryFailureCleansPartialRuntimeBeforeLease(t *testing.T) {
	f := newIndividualServiceFixture(t)
	f.deps.runtime = func(context.Context, string, individualServiceLease, enrollmentstore.InstallationBinding) (lifecycle.Runtime, error) {
		return &serviceRuntimeFixture{start: func() error { t.Fatal("failed factory runtime was started"); return nil }, stop: func() { f.mu.Lock(); defer f.mu.Unlock(); f.events = append(f.events, "partial-stop") }}, errors.New("fixture failure")
	}
	s := f.service()
	if err := s.Start(); err == nil {
		t.Fatal("failed factory reported ready")
	}
	s.Stop()
	assertServiceOrder(t, f.eventsCopy(), "partial-stop", "store-close", "lease-close")
}

func TestIndividualServiceConstructorFailureClosesOwnedResources(t *testing.T) {
	for _, stage := range []string{"open", "binding", "image"} {
		t.Run(stage, func(t *testing.T) {
			f := newIndividualServiceFixture(t)
			switch stage {
			case "open":
				f.deps.open = func(string) (individualServiceStore, error) { return nil, enrollmentstore.ErrUnavailable }
			case "binding":
				f.corrupt = true
			case "image":
				f.invalidImage = true
			}
			if s, err := newIndividualService(t.Context(), f.directory, f.deps); s != nil || err == nil {
				t.Fatal("broken installation constructed a service")
			}
			if f.held {
				t.Fatal("failed constructor leaked native service ownership")
			}
		})
	}
}

func TestIndividualServiceSelectionAndFailureNeverReturnTypedNilRuntime(t *testing.T) {
	legacyCalls, individualCalls := 0, 0
	legacy := func(context.Context) (*Agent, error) { legacyCalls++; return nil, errors.New("legacy fixture failure") }
	individual := func(context.Context, string) (lifecycle.Runtime, error) {
		individualCalls++
		return nil, errIndividualAgent
	}
	for _, tc := range []struct {
		mode, directory    string
		legacy, individual int
	}{{"", "", 1, 0}, {"true", t.TempDir(), 1, 1}, {"false", t.TempDir(), 1, 1}, {"TRUE", t.TempDir(), 1, 1}} {
		runtime, err := newServiceRuntime(t.Context(), tc.mode, tc.directory, legacy, individual)
		if runtime != nil || err == nil || !reflect.DeepEqual([]int{legacyCalls, individualCalls}, []int{tc.legacy, tc.individual}) {
			t.Fatal("service selection returned a typed nil or consulted the wrong mode")
		}
	}
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "invalid")
	t.Setenv("OPENUEM_AGENT_IDENTITY_DIRECTORY", "relative")
	if runtime, err := NewServiceRuntime(t.Context(), filepath.Join(t.TempDir(), "missing")); runtime != nil || err == nil {
		t.Fatal("failed explicit native service returned a typed nil")
	}
}

func TestIndividualServiceBorrowedLeaseIsValidatedBeforeNativeStoreAndNotClosedByFailedAgent(t *testing.T) {
	directory := t.TempDir()
	validated, closed := false, false
	lease := &serviceLeaseFixture{
		validate: func(got string) error {
			validated = true
			if got != directory {
				t.Error("borrowed ownership was not bound to requested installation")
			}
			return enrollmentstore.ErrUnavailable
		},
		close: func() error { closed = true; return nil },
	}
	if a, err := newAgentWithLease(t.Context(), "true", directory, lease); a != nil || err == nil {
		t.Fatal("invalid borrowed ownership opened an agent")
	}
	if !validated || closed {
		t.Fatal("failed generation did not preserve its supervisor's ownership")
	}
}

func TestIndividualServiceCancellationDuringGenerationStartupReturnsJoinedCancellation(t *testing.T) {
	f := newIndividualServiceFixture(t)
	entered, exited := make(chan struct{}), make(chan struct{})
	f.deps.runtime = func(ctx context.Context, _ string, _ individualServiceLease, _ enrollmentstore.InstallationBinding) (lifecycle.Runtime, error) {
		return &serviceRuntimeFixture{
			start: func() error { close(entered); <-ctx.Done(); return ctx.Err() },
			stop:  func() { close(exited) },
		}, nil
	}
	s := f.service()
	finished := make(chan error, 1)
	go func() { finished <- s.Start() }()
	<-entered
	s.Stop()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal("ordinary service stop became an initialization failure", err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("canceled generation startup was not joined")
	}
}
