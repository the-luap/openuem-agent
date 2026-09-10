//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-agent/internal/service/lifecycle"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var scmName = flag.String("openuem-lifecycle-fixture-service", "", "Unique isolated lifecycle test service")
var scmDirectory = flag.String("openuem-lifecycle-fixture-directory", "", "Directory for isolated lifecycle test gates")
var scmFailure = flag.Bool("openuem-lifecycle-fixture-failure", false, "Return an isolated startup failure")
var scmRecovery = flag.Bool("openuem-lifecycle-fixture-recovery", false, "Start an isolated controller with agent recovery pending")

func waitSCMGate(ctx context.Context, name string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := os.Stat(filepath.Join(*scmDirectory, name)); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func TestNativeSCMLifecycleHelper(t *testing.T) {
	if *scmName == "" || *scmDirectory == "" {
		t.Skip("isolated Local System subprocess only")
	}
	s := &OpenUEMService{factory: func(ctx context.Context) (lifecycle.Runtime, error) {
		ready, recovered := make(chan struct{}), make(chan struct{})
		recoveryStarted := false
		r := &serviceRuntime{start: func() error {
			if err := os.WriteFile(filepath.Join(*scmDirectory, "initializing"), []byte("fixture"), 0600); err != nil {
				return err
			}
			if *scmRecovery {
				recoveryStarted = true
				go func() {
					defer close(recovered)
					if waitSCMGate(ctx, "allow-start") == nil {
						_ = os.WriteFile(filepath.Join(*scmDirectory, "agent-ready"), []byte("fixture"), 0600)
						close(ready)
					}
				}()
				return nil
			}
			if err := waitSCMGate(ctx, "allow-start"); err != nil {
				return err
			}
			if *scmFailure {
				return errors.New("isolated startup failure")
			}
			return nil
		}, stop: func() {
			if recoveryStarted {
				<-recovered
			}
			_ = os.WriteFile(filepath.Join(*scmDirectory, "cleanup"), []byte("fixture"), 0600)
			// Cleanup owns its work even though the service lifetime is canceled.
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = waitSCMGate(cleanup, "allow-stop")
		}}
		if *scmRecovery {
			return &serviceReadyRuntime{serviceRuntime: r, ready: ready}, nil
		}
		return r, nil
	}}
	if err := svc.Run(*scmName, s); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSCMReportsInitializationAndJoinedCleanup(t *testing.T) {
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal("native lifecycle test requires service-manager access", err)
	}
	defer manager.Disconnect()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"ready", "startup-failure", "recovery"} {
		t.Run(scenario, func(t *testing.T) {
			failure, recovering := scenario == "startup-failure", scenario == "recovery"
			directory := t.TempDir()
			name := "OpenUEMLifecycleFixture-" + uuid.NewString()
			args := []string{"-test.run=^TestNativeSCMLifecycleHelper$", "-openuem-lifecycle-fixture-service=" + name, "-openuem-lifecycle-fixture-directory=" + directory}
			if failure {
				args = append(args, "-openuem-lifecycle-fixture-failure=true")
			}
			if recovering {
				args = append(args, "-openuem-lifecycle-fixture-recovery=true")
			}
			service, err := manager.CreateService(name, executable, mgr.Config{StartType: mgr.StartManual, DisplayName: name}, args...)
			if err != nil {
				t.Fatal(err)
			}
			writeGate := func(name string) {
				if err := os.WriteFile(filepath.Join(directory, name), []byte("fixture"), 0600); err != nil {
					t.Error(err)
				}
			}
			defer func() {
				writeGate("allow-start")
				writeGate("allow-stop")
				_, _ = service.Control(svc.Stop)
				deadline := time.Now().Add(15 * time.Second)
				for time.Now().Before(deadline) {
					status, err := service.Query()
					if err != nil || status.State == svc.Stopped {
						break
					}
					time.Sleep(20 * time.Millisecond)
				}
				if err := service.Delete(); err != nil {
					t.Error("isolated service could not be removed", err)
				}
				_ = service.Close()
			}()
			if err := service.Start(); err != nil {
				t.Fatal(err)
			}
			wait := func(want svc.State, marker string) svc.Status {
				t.Helper()
				deadline := time.Now().Add(15 * time.Second)
				for time.Now().Before(deadline) {
					status, err := service.Query()
					if err != nil {
						t.Fatal(err)
					}
					if status.State == want {
						if marker == "" {
							return status
						}
						if _, err := os.Stat(filepath.Join(directory, marker)); err == nil {
							return status
						}
					}
					if status.State == svc.Stopped || (failure && status.State == svc.Running) {
						t.Fatalf("unexpected native service state: %+v", status)
					}
					time.Sleep(20 * time.Millisecond)
				}
				t.Fatal("native service did not reach the required state")
				return svc.Status{}
			}
			var status svc.Status
			if !recovering {
				status = wait(svc.StartPending, "initializing")
				if status.Accepts != 0 {
					t.Fatal("native initialization prematurely accepted stop")
				}
				writeGate("allow-start")
			}
			if !failure {
				status = wait(svc.Running, "initializing")
				if status.Accepts != svc.AcceptStop|svc.AcceptShutdown {
					t.Fatal("native running service cannot stop")
				}
				if recovering {
					if _, err := os.Stat(filepath.Join(directory, "agent-ready")); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("unresolved recovery announced agent readiness")
					}
				}
				if _, err := service.Control(svc.Stop); err != nil {
					t.Fatal(err)
				}
			}
			status = wait(svc.StopPending, "cleanup")
			if recovering {
				if _, err := os.Stat(filepath.Join(directory, "agent-ready")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("SCM stop permitted an unresolved agent to start")
				}
			}
			if status.Accepts != 0 {
				t.Fatal("native cleanup reported active controls")
			}
			writeGate("allow-stop")
			status = wait(svc.Stopped, "")
			if failure {
				if status.Win32ExitCode != 1066 || status.ServiceSpecificExitCode != 1 {
					t.Fatalf("native startup failure lost exit code: %+v", status)
				}
			} else if status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0 {
				t.Fatalf("native stop failed: %+v", status)
			}
		})
	}
}
