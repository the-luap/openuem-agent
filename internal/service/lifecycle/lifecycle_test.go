package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeRuntime struct {
	start func() error
	stop  func()
}

func (f *fakeRuntime) Start() error { return f.start() }
func (f *fakeRuntime) Stop()        { f.stop() }

func TestLifecycleFailureAndCancellationNeverAnnounceReady(t *testing.T) {
	broken := errors.New("fixture initialization failed")
	for _, phase := range []string{"factory", "partial-factory", "missing-runtime", "cancel-factory", "start", "cancel-start"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var phases []Phase
			starts, stops := 0, 0
			f := &fakeRuntime{start: func() error {
				starts++
				if phase == "cancel-start" {
					cancel()
					return nil
				}
				return broken
			}, stop: func() {
				if len(phases) == 0 || phases[len(phases)-1] != Stopping {
					t.Error("cleanup began before stopping status")
				}
				stops++
			}}
			err := Run(ctx, func(context.Context) (Runtime, error) {
				switch phase {
				case "factory":
					return nil, broken
				case "partial-factory":
					return f, broken
				case "missing-runtime":
					return nil, nil
				case "cancel-factory":
					cancel()
				}
				return f, nil
			}, func(p Phase) { phases = append(phases, p) })
			if err == nil || !reflect.DeepEqual(phases, []Phase{Initializing, Stopping}) {
				t.Fatalf("unexpected lifecycle: %v, %v", phases, err)
			}
			wantStarts, wantStops := 0, 1
			if phase == "factory" || phase == "missing-runtime" {
				wantStops = 0
			}
			if phase == "start" || phase == "cancel-start" {
				wantStarts = 1
			}
			if starts != wantStarts || stops != wantStops {
				t.Fatalf("starts=%d stops=%d", starts, stops)
			}
		})
	}
}

func TestLifecycleReadyAndStopOwnTheSameRuntime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var phases []Phase
	started, stopped := false, false
	err := Run(ctx, func(parent context.Context) (Runtime, error) {
		if parent != ctx {
			t.Fatal("runtime did not inherit cancellation")
		}
		return &fakeRuntime{start: func() error { started = true; return nil }, stop: func() { stopped = true }}, nil
	}, func(phase Phase) {
		phases = append(phases, phase)
		if phase == Ready {
			if !started || stopped {
				t.Error("readiness preceded initialization")
			}
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || !stopped || !reflect.DeepEqual(phases, []Phase{Initializing, Ready, Stopping}) {
		t.Fatalf("unexpected lifecycle: %v, %v", phases, err)
	}
}

func TestLifecycleRejectsInvalidAndCanceledAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	factory := func(context.Context) (Runtime, error) { called = true; return nil, nil }
	notify := func(Phase) { called = true }
	for _, err := range []error{Run(nil, factory, notify), Run(context.Background(), nil, notify), Run(context.Background(), factory, nil), Run(ctx, factory, notify)} {
		if err == nil {
			t.Error("invalid lifecycle accepted")
		}
	}
	if called {
		t.Fatal("invalid lifecycle performed work")
	}
}

type recoveringRuntime struct {
	*fakeRuntime
	ready chan struct{}
}

func (r *recoveringRuntime) Ready() <-chan struct{} { return r.ready }

func TestLifecycleRecoveryDoesNotAnnounceAgentReadyAndOwnsCancellableCleanup(t *testing.T) {
	for _, result := range []string{"ready", "cancelled", "missing", "already-ready"} {
		t.Run(result, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var phases []Phase
			stopped := false
			r := &recoveringRuntime{fakeRuntime: &fakeRuntime{start: func() error { return nil }, stop: func() { stopped = true }}, ready: make(chan struct{})}
			if result == "missing" {
				r.ready = nil
			}
			if result == "already-ready" {
				close(r.ready)
			}
			err := Run(ctx, func(context.Context) (Runtime, error) { return r, nil }, func(phase Phase) {
				phases = append(phases, phase)
				if phase == Recovering {
					if result == "ready" {
						close(r.ready)
					} else {
						cancel()
					}
				}
				if phase == Ready {
					cancel()
				}
			})
			want := []Phase{Initializing, Recovering, Stopping}
			switch result {
			case "ready":
				want = []Phase{Initializing, Recovering, Ready, Stopping}
			case "already-ready":
				want = []Phase{Initializing, Ready, Stopping}
			case "missing":
				want = []Phase{Initializing, Stopping}
			}
			if err == nil || !stopped || !reflect.DeepEqual(phases, want) {
				t.Fatal("recovery confused controller initialization with agent readiness", phases, err)
			}
		})
	}
}
