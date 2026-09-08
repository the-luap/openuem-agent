package agent

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
)

type observedScheduler struct {
	gocron.Scheduler
	returned chan error
}

func (s *observedScheduler) Shutdown() error {
	err := s.Scheduler.Shutdown()
	s.returned <- err
	return err
}

func TestAgentInitializationErrorsReturnWithoutStartingWork(t *testing.T) {
	if a, err := New(nil); a != nil || err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a, err := New(ctx); a != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled initialization accepted", err)
	}
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "invalid")
	t.Setenv("OPENUEM_AGENT_IDENTITY_DIRECTORY", "")
	if a, err := New(context.Background()); a != nil || !errors.Is(err, errIndividualAgent) {
		t.Fatal("invalid mode accepted", err)
	}
	a := &Agent{}
	if err := a.Start(); err == nil {
		t.Fatal("uninitialized agent started")
	}
	a.Stop()
	a.Stop()
	if a, err := NewIndividual(context.Background(), ""); a != nil || !errors.Is(err, errIndividualAgent) {
		t.Fatal("explicit mode silently selected legacy credentials")
	}
	if a, err := NewIndividual(context.Background(), "relative"); a != nil || !errors.Is(err, errIndividualAgent) {
		t.Fatal("relative identity directory accepted")
	}
	if a, err := NewIndividual(ctx, filepath.Join(t.TempDir(), "identity")); a != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled explicit mode touched native storage", err)
	}
}

func TestStopJoinsSchedulerWorkAfterItsOwnTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler, err := gocron.NewScheduler(gocron.WithStopTimeout(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	identity := &enrollmentstore.Identity{Keys: &enrollment.Keys{}}
	observed := &observedScheduler{Scheduler: scheduler, returned: make(chan error, 1)}
	a := &Agent{ctx: ctx, cancel: cancel, TaskScheduler: observed, individual: &individualRuntime{ctx: ctx, cancel: cancel, identity: identity}}
	started, release, taskExited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	_, err = scheduler.NewJob(gocron.DurationJob(time.Hour), gocron.NewTask(a.tasks.wrap(func() {
		close(started)
		<-release
		close(taskExited)
	})), gocron.WithStartAt(gocron.WithStartImmediately()))
	if err != nil {
		t.Fatal(err)
	}
	scheduler.Start()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		a.Stop()
		t.Fatal("task did not start")
	}
	stopped, stoppedAgain := make(chan struct{}), make(chan struct{})
	go func() { a.Stop(); close(stopped) }()
	go func() { a.Stop(); close(stoppedAgain) }()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not cancel context")
	}
	// Observe the actual scheduler timeout, then check that it has not been
	// mistaken for completion of the underlying OS task.
	select {
	case err := <-observed.returned:
		if err == nil {
			t.Error("scheduler did not exercise its timeout")
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("scheduler did not return at its configured timeout")
	}
	select {
	case <-stopped:
		t.Error("stop returned while owned work was running")
	case <-stoppedAgain:
		t.Error("repeated stop returned while cleanup was running")
	default:
	}
	if identity.Keys == nil {
		t.Error("identity was released while owned work remained")
	}
	var called atomic.Bool
	a.tasks.wrap(func() { called.Store(true) })()
	if called.Load() {
		t.Error("shutdown admitted new work")
	}
	close(release)
	for _, done := range []<-chan struct{}{taskExited, stopped, stoppedAgain} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("owned cleanup did not finish")
		}
	}
	if identity.Keys != nil {
		t.Fatal("completed cleanup retained identity keys")
	}
}
