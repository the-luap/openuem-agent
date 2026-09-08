//go:build !windows

package activatecommand

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

var activationSignalFixture = flag.Bool("openuem-activation-signal-fixture", false, "Isolated activation cancellation fixture")

func TestActivationSignalHelper(t *testing.T) {
	if !*activationSignalFixture {
		t.Skip("isolated subprocess only")
	}
	_, code := handle(context.Background(), []string{"activate", "-identity-directory", filepath.Clean(os.TempDir())}, os.Stdout, os.Stderr, func(ctx context.Context, _ Options) (Result, error) {
		fmt.Fprintln(os.Stdout, "activation-waiting")
		<-ctx.Done()
		return Result{}, ctx.Err()
	})
	os.Exit(code)
}

func TestActivationSignalsCancelWaitingThroughThePublicCommand(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestActivationSignalHelper$", "-openuem-activation-signal-fixture")
			pipe, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			joined := false
			defer func() {
				if !joined {
					command.Process.Kill()
					command.Wait()
				}
			}()
			scanner := bufio.NewScanner(pipe)
			if !scanner.Scan() || scanner.Text() != "activation-waiting" {
				t.Fatal("activation fixture did not begin waiting")
			}
			if err := command.Process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			err = command.Wait()
			joined = true
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 130 {
				t.Fatal("activation did not cooperatively cancel", err)
			}
		})
	}
}
