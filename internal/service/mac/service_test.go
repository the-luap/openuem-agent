//go:build darwin

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/open-uem/openuem-agent/internal/service/lifecycle"
)

type signalRuntime struct {
	ctx             context.Context
	directory, mode string
}

func (r *signalRuntime) Start() error {
	if err := os.WriteFile(filepath.Join(r.directory, "starting"), []byte("fixture"), 0600); err != nil {
		return err
	}
	if r.mode == "starting" {
		<-r.ctx.Done()
	}
	return nil
}
func (r *signalRuntime) Stop() {
	_ = os.WriteFile(filepath.Join(r.directory, "stopped"), []byte("fixture"), 0600)
}

func TestServiceSignalHelper(t *testing.T) {
	directory := os.Getenv("OPENUEM_SIGNAL_FIXTURE_DIRECTORY")
	if directory == "" {
		t.Skip("isolated subprocess only")
	}
	mode := os.Getenv("OPENUEM_SIGNAL_FIXTURE_MODE")
	s := &OpenUEMService{factory: func(ctx context.Context) (lifecycle.Runtime, error) {
		if mode == "failure" {
			return nil, errors.New("fixture startup error")
		}
		return &signalRuntime{ctx: ctx, directory: directory, mode: mode}, nil
	}}
	if err := s.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestServiceSignalsAreHandledDuringStartupAndRunning(t *testing.T) {
	for _, mode := range []string{"starting", "running", "failure"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestServiceSignalHelper$")
			cmd.Env = append(os.Environ(), "OPENUEM_SIGNAL_FIXTURE_DIRECTORY="+directory, "OPENUEM_SIGNAL_FIXTURE_MODE="+mode)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if mode != "failure" {
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for {
					if _, err := os.Stat(filepath.Join(directory, "starting")); err == nil {
						break
					}
					select {
					case <-ticker.C:
					case <-ctx.Done():
						_ = cmd.Wait()
						t.Fatal("fixture did not initialize")
					}
				}
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			err = cmd.Wait()
			if ctx.Err() != nil {
				t.Fatal("service did not finish", ctx.Err())
			}
			if mode == "failure" {
				var status *exec.ExitError
				if !errors.As(err, &status) || status.ExitCode() != 1 {
					t.Fatal("failed startup returned success", err)
				}
				return
			}
			if err != nil {
				t.Fatal("termination skipped orderly cleanup", err)
			}
			if _, err := os.Stat(filepath.Join(directory, "stopped")); err != nil {
				t.Fatal("service did not release its runtime", err)
			}
		})
	}
}
