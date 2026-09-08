// Package macsecurity performs narrowly scoped local Mac security checks.
package macsecurity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"
)

var (
	ErrUnavailable = errors.New("FileVault recovery validation is unavailable")
	ErrUnsupported = errors.New("FileVault recovery validation requires the root Mac agent")
)

// ValidateFileVaultRecoveryKey checks the mounted Mac volume without changing
// encryption or any recovery key. The caller owns and must clear key. Neither
// the key nor process output is returned in errors, written to disk, placed in
// arguments/environment variables, or sent to a shell.
func ValidateFileVaultRecoveryKey(ctx context.Context, key []byte) (bool, error) {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		return false, ErrUnsupported
	}
	return validateFileVaultRecoveryKey(ctx, key, exec.CommandContext)
}

type commandFactory func(context.Context, string, ...string) *exec.Cmd

func validateFileVaultRecoveryKey(ctx context.Context, key []byte, command commandFactory) (bool, error) {
	if ctx == nil || command == nil || !validRecoveryKey(key) {
		return false, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return false, ErrUnavailable
	}
	// The strict ASCII key format cannot contain XML metacharacters. Construct
	// owned bytes directly rather than retaining an immutable secret string.
	input := fileVaultPasswordInput(key)
	defer clear(input)
	cmd := command(ctx, "/usr/bin/fdesetup", "validaterecovery", "-inputplist")
	if cmd == nil {
		return false, ErrUnavailable
	}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 500 * time.Millisecond
	output := &validationOutput{}
	defer clear(output.data[:])
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || output.overflow || ctx.Err() != nil {
		return false, ErrUnavailable
	}
	result := bytes.TrimSpace(output.data[:output.length])
	if bytes.Equal(result, []byte("true")) {
		return true, nil
	}
	if bytes.Equal(result, []byte("false")) {
		return false, nil
	}
	return false, ErrUnavailable
}

func validRecoveryKey(key []byte) bool {
	if len(key) != 29 {
		return false
	}
	for i, b := range key {
		if i%5 == 4 {
			if b != '-' {
				return false
			}
		} else if !(b >= 'A' && b <= 'Z' || b >= '0' && b <= '9') {
			return false
		}
	}
	return true
}

// Drain oversized output without retaining it. The process deadline bounds a
// misbehaving tool, including descendants retaining output pipes after exit.
type validationOutput struct {
	data     [64]byte
	length   int
	overflow bool
}

func (o *validationOutput) Write(data []byte) (int, error) {
	n := copy(o.data[o.length:], data)
	o.length += n
	if n != len(data) {
		o.overflow = true
	}
	return len(data), nil
}
