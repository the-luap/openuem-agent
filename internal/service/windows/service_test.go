//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/openuem-agent/internal/logger"
	"github.com/open-uem/openuem-agent/internal/service/lifecycle"
	"golang.org/x/sys/windows/svc"
)

type serviceRuntime struct {
	start func() error
	stop  func()
}

func (r *serviceRuntime) Start() error { return r.start() }
func (r *serviceRuntime) Stop()        { r.stop() }

type serviceResult struct {
	specific bool
	code     uint32
}

func receiveStatus(t *testing.T, changes <-chan svc.Status, state svc.State) svc.Status {
	t.Helper()
	select {
	case got := <-changes:
		if got.State != state {
			t.Fatalf("service state = %v, want %v", got.State, state)
		}
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("service status was not reported")
	}
	return svc.Status{}
}

func receiveResult(t *testing.T, done <-chan serviceResult, specific bool, code uint32) {
	t.Helper()
	select {
	case result := <-done:
		if result.specific != specific || result.code != code {
			t.Fatalf("unexpected service result: %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service did not finish")
	}
}

func TestServiceInitializationFailureIsNeverRunning(t *testing.T) {
	for _, where := range []string{"factory", "start"} {
		t.Run(where, func(t *testing.T) {
			controls, changes := make(chan svc.ChangeRequest, 4), make(chan svc.Status, 8)
			done := make(chan serviceResult, 1)
			release := make(chan struct{})
			var stopped atomic.Int32
			s := &OpenUEMService{factory: func(context.Context) (lifecycle.Runtime, error) {
				<-release
				if where == "factory" {
					return nil, errors.New("fixture failure")
				}
				return &serviceRuntime{start: func() error { return errors.New("fixture failure") }, stop: func() { stopped.Add(1) }}, nil
			}}
			go func() { specific, code := s.Execute(nil, controls, changes); done <- serviceResult{specific, code} }()
			status := receiveStatus(t, changes, svc.StartPending)
			if status.Accepts != 0 || status.WaitHint == 0 {
				t.Fatal("initialization accepted controls or omitted wait hint")
			}
			controls <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.Running}}
			receiveStatus(t, changes, svc.StartPending)
			close(release)
			receiveStatus(t, changes, svc.StopPending)
			receiveResult(t, done, true, 1)
			want := int32(0)
			if where == "start" {
				want = 1
			}
			if stopped.Load() != want {
				t.Fatal("partial runtime cleanup count", stopped.Load())
			}
			if len(changes) != 0 {
				t.Fatal("unexpected extra status")
			}
		})
	}
}

func TestServiceControlsAndLoggerRemainAvailableDuringCleanup(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "service.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	controls, changes := make(chan svc.ChangeRequest, 8), make(chan svc.Status, 8)
	done := make(chan serviceResult, 1)
	cleanupStarted, release := make(chan struct{}), make(chan struct{})
	var stopped atomic.Int32
	s := &OpenUEMService{Logger: &logger.OpenUEMLogger{LogFile: file}, factory: func(context.Context) (lifecycle.Runtime, error) {
		return &serviceRuntime{start: func() error { return nil }, stop: func() {
			stopped.Add(1)
			if _, err := file.WriteString("cleanup started\n"); err != nil {
				t.Error("logger was closed before cleanup", err)
			}
			close(cleanupStarted)
			<-release
		}}, nil
	}}
	go func() { specific, code := s.Execute(nil, controls, changes); done <- serviceResult{specific, code} }()
	receiveStatus(t, changes, svc.StartPending)
	status := receiveStatus(t, changes, svc.Running)
	if status.Accepts != svc.AcceptStop|svc.AcceptShutdown {
		t.Fatal("running service does not accept stop/shutdown")
	}
	controls <- svc.ChangeRequest{Cmd: svc.Pause}
	controls <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.Stopped}}
	receiveStatus(t, changes, svc.Running)
	controls <- svc.ChangeRequest{Cmd: svc.Stop}
	receiveStatus(t, changes, svc.StopPending)
	select {
	case <-cleanupStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not start")
	}
	controls <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.Running}}
	receiveStatus(t, changes, svc.StopPending)
	select {
	case <-done:
		t.Fatal("service returned before cleanup finished")
	default:
	}
	close(release)
	receiveResult(t, done, false, 0)
	if stopped.Load() != 1 {
		t.Fatal("cleanup did not run once")
	}
	if _, err := file.WriteString("after stop"); err == nil {
		t.Fatal("logger remained open after cleanup")
	}
}

func TestServiceStopDuringInitializationWaitsWithoutRunning(t *testing.T) {
	controls, changes := make(chan svc.ChangeRequest, 4), make(chan svc.Status, 8)
	done := make(chan serviceResult, 1)
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var stopped atomic.Int32
	var starting atomic.Bool
	s := &OpenUEMService{factory: func(ctx context.Context) (lifecycle.Runtime, error) {
		return &serviceRuntime{start: func() error {
			starting.Store(true)
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			starting.Store(false)
			return nil
		}, stop: func() {
			if starting.Load() {
				t.Error("cleanup raced with initialization")
			}
			stopped.Add(1)
		}}, nil
	}}
	go func() { specific, code := s.Execute(nil, controls, changes); done <- serviceResult{specific, code} }()
	receiveStatus(t, changes, svc.StartPending)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("initialization did not start")
	}
	controls <- svc.ChangeRequest{Cmd: svc.Shutdown}
	receiveStatus(t, changes, svc.StopPending)
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("initialization was not canceled")
	}
	controls <- svc.ChangeRequest{Cmd: svc.Interrogate}
	receiveStatus(t, changes, svc.StopPending)
	select {
	case <-done:
		t.Fatal("service returned before initialization joined")
	default:
	}
	close(release)
	receiveResult(t, done, false, 0)
	if stopped.Load() != 1 || len(changes) != 0 {
		t.Fatal("canceled initialization leaked ownership or reported running")
	}
}
