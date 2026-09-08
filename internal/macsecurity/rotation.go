package macsecurity

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"
)

const maxRotationOutput = 8192

// FileVaultRotation owns a candidate new PRK. Key returns borrowed bytes; Close
// clears them. Process output and plaintext keys never appear in diagnostics.
type FileVaultRotation struct {
	outcome string
	key     []byte
}

func (*FileVaultRotation) String() string               { return "[private FileVault rotation result]" }
func (r *FileVaultRotation) GoString() string           { return r.String() }
func (*FileVaultRotation) MarshalJSON() ([]byte, error) { return nil, ErrRotationUnavailable }
func (r *FileVaultRotation) Outcome() string {
	if r == nil {
		return "unavailable"
	}
	return r.outcome
}
func (r *FileVaultRotation) Key() []byte {
	if r == nil {
		return nil
	}
	return r.key
}
func (r *FileVaultRotation) Close() {
	if r != nil {
		clear(r.key)
		r.key = nil
	}
}

// RotateFileVaultRecoveryKey requires the current private process lease and an
// already committed, exclusively admitted journal intent. The caller must verify
// native escrow readiness and reserve certificate lifetime for signing/persisting
// the returned result. This function never retries a mutation or reboots a Mac.
func RotateFileVaultRecoveryKey(ctx context.Context, lease *RotationLease, key []byte) *FileVaultRotation {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		return &FileVaultRotation{outcome: "unsupported"}
	}
	return rotateFileVaultWithLease(ctx, lease, key, exec.CommandContext)
}

func rotateFileVaultWithLease(ctx context.Context, lease *RotationLease, key []byte, command commandFactory) *FileVaultRotation {
	if lease == nil {
		return &FileVaultRotation{outcome: "unavailable"}
	}
	lease.mu.RLock()
	defer lease.mu.RUnlock()
	if lease.file == nil {
		return &FileVaultRotation{outcome: "unavailable"}
	}
	if _, err := lease.file.Stat(); err != nil {
		return &FileVaultRotation{outcome: "unavailable"}
	}
	return rotateFileVaultRecoveryKey(ctx, key, command)
}

func rotateFileVaultRecoveryKey(ctx context.Context, key []byte, command commandFactory) *FileVaultRotation {
	r := &FileVaultRotation{outcome: "unavailable"}
	if ctx == nil || command == nil || !validRecoveryKey(key) {
		return r
	}
	ctx, stop := context.WithTimeout(ctx, time.Minute)
	defer stop()
	if ctx.Err() != nil {
		return r
	}
	valid, err := validateFileVaultRecoveryKey(ctx, key, command)
	if err != nil || ctx.Err() != nil {
		return r
	}
	if !valid {
		r.outcome = "invalid"
		return r
	}
	input := fileVaultPasswordInput(key)
	defer clear(input)
	mutation, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := command(mutation, "/usr/bin/fdesetup", "changerecovery", "-personal", "-inputplist", "-outputplist")
	if cmd == nil || mutation.Err() != nil {
		return r
	}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 500 * time.Millisecond
	output := &rotationOutput{}
	defer clear(output.data[:])
	cmd.Stdout, cmd.Stderr = output, io.Discard
	if err := cmd.Start(); err != nil {
		return r
	}
	// Once started, absence of a trustworthy returned key cannot establish that
	// the OS left its key unchanged. Never map it to a retryable preflight error.
	r.outcome = "uncertain"
	runErr := cmd.Wait()
	if output.overflow {
		return r
	}
	newKey, err := rotationKeyFromPlist(output.data[:output.length])
	if err != nil {
		return r
	}
	if bytes.Equal(newKey, key) {
		clear(newKey)
		return r
	}
	r.key, r.outcome = newKey, "unverified"
	// A changed key is valuable even after a process error or cancellation.
	// Preserve the candidate immediately instead of dropping it with the error.
	if runErr != nil || mutation.Err() != nil || ctx.Err() != nil {
		return r
	}
	valid, err = validateFileVaultRecoveryKey(ctx, newKey, command)
	if err == nil && ctx.Err() == nil && valid {
		r.outcome = "rotated"
	}
	return r
}

func fileVaultPasswordInput(key []byte) []byte {
	const prefix = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Password</key><string>`
	const suffix = `</string></dict></plist>`
	input := make([]byte, len(prefix)+len(key)+len(suffix))
	copy(input, prefix)
	copy(input[len(prefix):], key)
	copy(input[len(prefix)+len(key):], suffix)
	return input
}

type rotationOutput struct {
	data     [maxRotationOutput]byte
	length   int
	overflow bool
}

func (o *rotationOutput) Write(data []byte) (int, error) {
	n := copy(o.data[o.length:], data)
	o.length += n
	if n != len(data) {
		o.overflow = true
	}
	return len(data), nil
}
