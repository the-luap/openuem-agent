package macservice

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type fakeNativeService struct {
	state                 Status
	registrations, closes int
	registerAction        func() error
	statusAction          func()
}

func (n *fakeNativeService) status() (Status, error) {
	if n.statusAction != nil {
		n.statusAction()
	}
	return n.state, nil
}
func (n *fakeNativeService) register() error {
	n.registrations++
	if n.registerAction != nil {
		return n.registerAction()
	}
	n.state = Enabled
	return nil
}
func (n *fakeNativeService) close() error { n.closes++; return nil }

func TestRegistrationPreservesAuthorizationAndRechecksAdmission(t *testing.T) {
	for _, scenario := range []string{"new", "enabled", "approval", "missing", "unknown", "signature", "failed", "persisted-error", "cancel-before", "cancel-before-register", "cancel-after-register"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			n := &fakeNativeService{state: NotRegistered}
			want, wantError, wantCalls := Enabled, false, 1
			s := &Service{native: n, check: func(ctx context.Context, signature bool) error { return ctx.Err() }}
			switch scenario {
			case "enabled":
				n.state, wantCalls = Enabled, 0
			case "approval":
				n.state, want, wantCalls = RequiresApproval, RequiresApproval, 0
			case "missing":
				n.state, wantError, wantCalls = NotFound, true, 0
			case "unknown":
				n.state, wantError, wantCalls = 99, true, 0
			case "signature":
				wantError, wantCalls = true, 0
				s.check = func(context.Context, bool) error { return ErrSignature }
			case "failed":
				wantError = true
				n.registerAction = func() error { return ErrRegistration }
			case "persisted-error":
				n.registerAction = func() error { n.state = Enabled; return ErrRegistration }
			case "cancel-before":
				cancel()
				wantError, wantCalls = true, 0
			case "cancel-before-register":
				n.statusAction = cancel
				wantError, wantCalls = true, 0
			case "cancel-after-register":
				wantError = true
				n.registerAction = func() error { n.state = RequiresApproval; cancel(); return nil }
			}
			status, err := s.Register(ctx)
			if (err != nil) != wantError || (!wantError && status != want) || n.registrations != wantCalls {
				t.Fatal("unexpected registration transition", status, err, n.registrations)
			}
			if scenario == "cancel-after-register" && (status != RequiresApproval || !errors.Is(err, context.Canceled)) {
				t.Fatal("cancellation lost the persisted registration", status, err)
			}
			s.Close()
			s.Close()
			if n.closes != 1 {
				t.Fatal("native handle was not closed exactly once")
			}
			if _, err := s.Status(context.Background()); !errors.Is(err, ErrAccess) {
				t.Fatal("closed handle remained usable")
			}
		})
	}
}

func TestConcurrentRegistrationUsesOneNativeMutation(t *testing.T) {
	n := &fakeNativeService{state: NotRegistered}
	s := &Service{native: n, check: func(ctx context.Context, _ bool) error { return ctx.Err() }}
	defer s.Close()
	var work sync.WaitGroup
	for range 8 {
		work.Go(func() {
			status, err := s.Register(context.Background())
			if err != nil || status != Enabled {
				t.Error(status, err)
			}
		})
	}
	work.Wait()
	if n.registrations != 1 {
		t.Fatal("concurrent callers re-registered a live service")
	}
}
