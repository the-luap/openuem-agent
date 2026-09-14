//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

// readNativePackage runs a fixed read-only system utility as the service
// identity, with no inherited credentials, proxy, loader or user configuration.
// Both diagnostic streams share a byte budget. Every started process is waited
// for, including cancellation and parser failure, before returning to the owner.
func readNativePackage(parent context.Context, executable string, args []string, limit int64, consume func(io.Reader) error) error {
	if parent == nil || !filepath.IsAbs(executable) || consume == nil || limit < 1 || limit > 512<<20 {
		return ErrMetadata
	}
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	var count atomic.Int64
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	command.Stdout = inspectionOutput{writer, &count, limit, cancel}
	command.Stderr = inspectionOutput{io.Discard, &count, limit, cancel}
	if err := command.Start(); err != nil {
		return contextError(parent, ErrMetadata)
	}
	done := make(chan error, 1)
	go func() {
		err := command.Wait()
		_ = writer.CloseWithError(err)
		done <- err
	}()
	parseErr := consume(contextReader{ctx, reader})
	if parseErr == nil {
		var trailing [1]byte
		if n, err := (contextReader{ctx, reader}).Read(trailing[:]); n != 0 || err != io.EOF {
			parseErr = ErrMetadata
		}
	}
	if parseErr != nil {
		cancel()
		_ = reader.Close()
	}
	runErr := <-done
	if runErr != nil || parseErr != nil || count.Load() > limit || ctx.Err() != nil {
		return contextError(parent, ErrMetadata)
	}
	return nil
}

type inspectionOutput struct {
	writer io.Writer
	count  *atomic.Int64
	limit  int64
	cancel context.CancelFunc
}

func (w inspectionOutput) Write(data []byte) (int, error) {
	if w.count.Add(int64(len(data))) > w.limit {
		w.cancel()
		return 0, ErrMetadata
	}
	return w.writer.Write(data)
}
