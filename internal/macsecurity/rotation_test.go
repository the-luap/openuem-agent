package macsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

const fixtureNewRecoveryKey = "1111-2222-3333-4444-5555-6666"
const fixtureRotationPlist = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Change</key><true/><key>RecoveryKey</key><string>` + fixtureNewRecoveryKey + `</string><key>EnableDate</key><date>2026-09-08T12:00:00Z</date><key>SerialNumber</key><string>SYNTHETIC-FIXTURE</string></dict></plist>`

// This subprocess is the Go test executable. It checks real stdin/environment
// handling and emits synthetic output; no test executes the host's fdesetup.
func TestFileVaultRotationProcess(t *testing.T) {
	index := slices.Index(os.Args, "--filevault-rotation-fixture")
	if index < 0 {
		return
	}
	if index+1 >= len(os.Args) || os.Getenv("OPENUEM_ROTATION_TEST_SECRET") != "" || os.Getenv("PATH") != "/usr/bin:/bin:/usr/sbin:/sbin" || os.Getenv("LANG") != "C" || os.Getenv("LC_ALL") != "C" {
		os.Exit(91)
	}
	mode := os.Args[index+1]
	expected := fixtureRecoveryKey
	if strings.HasPrefix(mode, "after-") {
		expected = fixtureNewRecoveryKey
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil || len(input) > 4096 {
		os.Exit(92)
	}
	var decoded map[string]any
	if _, err = plist.Unmarshal(input, &decoded); err != nil || len(decoded) != 1 || decoded["Password"] != expected {
		os.Exit(93)
	}
	clear(input)
	switch mode {
	case "before-valid", "after-valid":
		_, _ = io.WriteString(os.Stdout, "true\n")
	case "before-invalid", "after-invalid":
		_, _ = io.WriteString(os.Stdout, "false\n")
	case "before-failed", "after-failed":
		_, _ = io.WriteString(os.Stderr, expected)
		os.Exit(1)
	case "rotated", "key-error", "key-timeout":
		_, _ = io.WriteString(os.Stdout, fixtureRotationPlist)
		if mode == "key-error" {
			_, _ = io.WriteString(os.Stderr, fixtureNewRecoveryKey)
			os.Exit(1)
		}
		if mode == "key-timeout" {
			time.Sleep(10 * time.Second)
		}
	case "same-key":
		_, _ = io.WriteString(os.Stdout, strings.ReplaceAll(fixtureRotationPlist, fixtureNewRecoveryKey, fixtureRecoveryKey))
	case "duplicate-key":
		_, _ = io.WriteString(os.Stdout, strings.Replace(fixtureRotationPlist, `</dict>`, `<key>RecoveryKey</key><string>`+fixtureNewRecoveryKey+`</string></dict>`, 1))
	case "oversized":
		_, _ = io.WriteString(os.Stdout, fixtureRotationPlist+strings.Repeat(" ", maxRotationOutput))
	case "malformed":
		_, _ = io.WriteString(os.Stdout, fixtureRotationPlist[:len(fixtureRotationPlist)-1])
	case "missing-key":
		_, _ = io.WriteString(os.Stdout, `<plist version="1.0"><dict><key>Change</key><true/></dict></plist>`)
	case "no-output":
	case "timeout":
		time.Sleep(10 * time.Second)
	default:
		os.Exit(94)
	}
	os.Exit(0)
}

func TestFileVaultRotationPreservesKeysAndNeverRetriesMutation(t *testing.T) {
	t.Setenv("OPENUEM_ROTATION_TEST_SECRET", "must-not-be-inherited")
	for _, tc := range []struct {
		before, mutation, after, outcome string
		wantKey                          bool
		calls                            int
	}{
		{"valid", "rotated", "valid", "rotated", true, 3},
		{"valid", "rotated", "invalid", "unverified", true, 3},
		{"valid", "rotated", "failed", "unverified", true, 3},
		{"valid", "rotated", "cancelled", "unverified", true, 3},
		{"invalid", "", "", "invalid", false, 1},
		{"failed", "", "", "unavailable", false, 1},
		{"valid", "start-failed", "", "unavailable", false, 2},
		{"valid", "nil-command", "", "unavailable", false, 2},
		{"valid", "key-error", "", "unverified", true, 2},
		{"valid", "key-timeout", "", "unverified", true, 2},
		{"valid", "same-key", "", "uncertain", false, 2},
		{"valid", "duplicate-key", "", "uncertain", false, 2},
		{"valid", "oversized", "", "uncertain", false, 2},
		{"valid", "malformed", "", "uncertain", false, 2},
		{"valid", "missing-key", "", "uncertain", false, 2},
		{"valid", "no-output", "", "uncertain", false, 2},
		{"valid", "timeout", "", "uncertain", false, 2},
	} {
		t.Run(tc.before+"/"+tc.mutation+"/"+tc.after, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls, mutations := 0, 0
			factory := func(ctx context.Context, path string, args ...string) *exec.Cmd {
				calls++
				if path != "/usr/bin/fdesetup" {
					t.Fatal("wrong command path")
				}
				mode, limit := "", 15*time.Second
				if calls == 1 || calls == 3 {
					if !slices.Equal(args, []string{"validaterecovery", "-inputplist"}) {
						t.Fatal("unexpected validation arguments")
					}
					mode = "before-" + tc.before
					if calls == 3 {
						mode = "after-" + tc.after
					}
					if mode == "after-cancelled" {
						cancel()
						mode = "after-valid"
					}
				} else {
					if !slices.Equal(args, []string{"changerecovery", "-personal", "-inputplist", "-outputplist"}) {
						t.Fatal("unexpected mutation arguments or secret in arguments")
					}
					mutations++
					mode, limit = tc.mutation, 30*time.Second
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > limit+time.Millisecond {
					t.Fatal("unbounded process context")
				}
				if mode == "nil-command" {
					return nil
				}
				if mode == "start-failed" {
					return exec.CommandContext(ctx, filepath.Join(t.TempDir(), "missing-fixture-executable"))
				}
				if mode == "timeout" || mode == "key-timeout" {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 2*time.Second)
					t.Cleanup(stop)
				}
				return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileVaultRotationProcess$", "--", "--filevault-rotation-fixture", mode)
			}
			oldKey := []byte(fixtureRecoveryKey)
			r := rotateFileVaultRecoveryKey(ctx, oldKey, factory)
			defer r.Close()
			if r.Outcome() != tc.outcome || (len(r.Key()) != 0) != tc.wantKey || calls != tc.calls || mutations > 1 {
				t.Fatal("wrong rotation outcome or repeated mutation", r.Outcome(), calls, mutations)
			}
			started := tc.before == "valid" && tc.mutation != "start-failed" && tc.mutation != "nil-command"
			if r.ExecutionStopped() != started {
				t.Fatal("stopping evidence does not match reaped mutation process")
			}
			if !bytes.Equal(oldKey, []byte(fixtureRecoveryKey)) {
				t.Fatal("driver modified the caller's old key")
			}
			if tc.wantKey && (!bytes.Equal(r.Key(), []byte(fixtureNewRecoveryKey)) || cap(r.Key()) != 29) {
				t.Fatal("returned candidate key was lost or widened")
			}
			if _, err := json.Marshal(r); err == nil {
				t.Fatal("result has an accidental JSON representation")
			}
			if strings.Contains(fmt.Sprintf("%v %#v", r, r), fixtureNewRecoveryKey) {
				t.Fatal("result representation exposed the candidate")
			}
			borrowed := r.Key()
			r.Close()
			if r.Key() != nil || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("candidate was not cleared")
			}
		})
	}
}

func TestFileVaultRotationRejectsInputAndUnavailableLeaseBeforeExecution(t *testing.T) {
	factory := func(context.Context, string, ...string) *exec.Cmd {
		t.Fatal("invalid input reached a process")
		return nil
	}
	for _, key := range []string{"", fixtureRecoveryKey + "\n", strings.ToLower(fixtureRecoveryKey), strings.ReplaceAll(fixtureRecoveryKey, "A", "<")} {
		if r := rotateFileVaultRecoveryKey(t.Context(), []byte(key), factory); r.Outcome() != "unavailable" || r.Key() != nil {
			t.Fatal("invalid input accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, r := range []*FileVaultRotation{
		rotateFileVaultRecoveryKey(ctx, []byte(fixtureRecoveryKey), factory),
		rotateFileVaultRecoveryKey(nil, []byte(fixtureRecoveryKey), factory),
		rotateFileVaultRecoveryKey(t.Context(), []byte(fixtureRecoveryKey), nil),
		rotateFileVaultWithLease(t.Context(), nil, []byte(fixtureRecoveryKey), factory),
		rotateFileVaultWithLease(t.Context(), &RotationLease{}, []byte(fixtureRecoveryKey), factory),
	} {
		if r.Outcome() != "unavailable" || r.Key() != nil {
			t.Fatal("unavailable context or lease accepted")
		}
	}
	file, err := os.CreateTemp(t.TempDir(), "closed-lease-")
	if err != nil {
		t.Fatal(err)
	}
	lease := &RotationLease{file: file}
	lease.Close()
	if r := rotateFileVaultWithLease(t.Context(), lease, []byte(fixtureRecoveryKey), factory); r.Outcome() != "unavailable" {
		t.Fatal("closed lease admitted execution")
	}
}

func TestFileVaultRotationLeaseCloseJoinsTheActiveDriver(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "owned-lease-")
	if err != nil {
		t.Fatal(err)
	}
	lease := &RotationLease{file: file}
	defer lease.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	done, closed := make(chan *FileVaultRotation, 1), make(chan error, 1)
	go func() {
		done <- rotateFileVaultWithLease(ctx, lease, []byte(fixtureRecoveryKey), func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
			close(entered)
			<-release
			return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileVaultRotationProcess$", "--", "--filevault-rotation-fixture", "before-valid")
		})
	}()
	<-entered
	go func() { closed <- lease.Close() }()
	select {
	case <-closed:
		t.Fatal("lease closed while the driver still owned it")
	case <-time.After(25 * time.Millisecond):
	}
	cancel()
	close(release)
	if r := <-done; r.Outcome() != "unavailable" {
		t.Fatal("cancelled preflight performed mutation")
	}
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
}
