// Package packagesignature checks native installer signatures without installing
// or executing the candidate. Release authorization and byte hashes are separate.
package packagesignature

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
)

var ErrUntrusted = errors.New("the installer native signature could not be verified")

const (
	verificationTimeout = 2 * time.Minute
	maxDiagnosticSize   = 16 << 10
	helperArgument      = "--openuem-verify-installer-signature"
)

// Verify requires a staged, regular installer in a private directory under a
// trusted parent. Callers must verify the separately signed release and hash the
// same file before and after this check; keep its path protected until use. A
// successful native signature does not itself authorize an OpenUEM release.
// Native subprocesses have a two-minute deadline and are joined after cancellation.
func Verify(ctx context.Context, path, format string) error {
	if ctx == nil {
		return ErrUntrusted
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validCandidate(path, format) {
		return ErrUntrusted
	}
	ctx, cancel := context.WithTimeout(ctx, verificationTimeout)
	defer cancel()
	return verifyNative(ctx, path, format)
}

func validCandidate(path, format string) bool {
	if !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Ext(path) != "."+format {
		return false
	}
	if (runtime.GOOS == "windows" && format != "exe" && format != "msi") || (runtime.GOOS == "darwin" && format != "pkg") || (runtime.GOOS != "windows" && runtime.GOOS != "darwin") {
		return false
	}
	if runtime.GOOS == "windows" {
		volume := filepath.VolumeName(path)
		if len(volume) != 2 || volume[1] != ':' || !((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z')) {
			return false
		}
	}
	for _, r := range path {
		if unicode.IsControl(r) {
			return false
		}
	}
	if err := keyfile.CheckDirectory(filepath.Dir(path)); err != nil {
		return false
	}
	file, err := keyfile.Open(path, artifacts.MaxPackageSize)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	return err == nil && info.Size() > 0
}

// boundedOutput discards excess diagnostics while draining the subprocess pipe.
// Diagnostic contents are never returned to callers or application logs.
type boundedOutput struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(data)
	remaining := maxDiagnosticSize - len(b.data)
	if len(data) > remaining {
		b.overflow = true
		data = data[:remaining]
	}
	b.data = append(b.data, data...)
	return n, nil
}

func runCheck(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	var output boundedOutput
	command.Stdout = &output
	command.Stderr = &output
	command.Stdin = nil
	command.WaitDelay = time.Second
	err := command.Run()
	if ctx.Err() != nil {
		clear(output.data)
		return nil, ctx.Err()
	}
	if err != nil || output.overflow {
		clear(output.data)
		return nil, ErrUntrusted
	}
	return output.data, nil
}
