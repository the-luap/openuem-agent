package macsecurity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

const fixtureRecoveryKey = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"

// This helper is the test executable, never fdesetup. It validates actual stdin
// and process configuration before emitting a chosen simulated tool response.
func TestFileVaultValidationProcess(t *testing.T) {
	index := slices.Index(os.Args, "--filevault-validation-fixture")
	if index < 0 {
		return
	}
	if index+1 >= len(os.Args) || os.Getenv("OPENUEM_FILEVAULT_TEST_SECRET") != "" || os.Getenv("LANG") != "C" || os.Getenv("LC_ALL") != "C" {
		os.Exit(91)
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil || len(input) > 4096 {
		os.Exit(92)
	}
	var decoded map[string]any
	if _, err = plist.Unmarshal(input, &decoded); err != nil || len(decoded) != 1 || decoded["Password"] != fixtureRecoveryKey {
		os.Exit(93)
	}
	clear(input)
	switch os.Args[index+1] {
	case "valid":
		_, _ = io.WriteString(os.Stdout, "true\n")
	case "invalid":
		_, _ = io.WriteString(os.Stdout, "false\n")
	case "failed":
		_, _ = io.WriteString(os.Stdout, "true\n")
		_, _ = io.WriteString(os.Stderr, fixtureRecoveryKey)
		os.Exit(1)
	case "unexpected":
		_, _ = io.WriteString(os.Stdout, fixtureRecoveryKey)
	case "oversized":
		_, _ = io.WriteString(os.Stdout, strings.Repeat("true\n", 200))
	case "timeout":
		time.Sleep(10 * time.Second)
	default:
		os.Exit(94)
	}
	os.Exit(0)
}

func TestFileVaultValidationUsesOnlyStdinAndExactResult(t *testing.T) {
	t.Setenv("OPENUEM_FILEVAULT_TEST_SECRET", "must-not-be-inherited")
	for _, tc := range []struct {
		mode  string
		valid bool
		fail  bool
	}{
		{"valid", true, false}, {"invalid", false, false}, {"failed", false, true},
		{"unexpected", false, true}, {"oversized", false, true}, {"timeout", false, true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ctx := t.Context()
			if tc.mode == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			key := []byte(fixtureRecoveryKey)
			factory := func(ctx context.Context, path string, args ...string) *exec.Cmd {
				if path != "/usr/bin/fdesetup" || !slices.Equal(args, []string{"validaterecovery", "-inputplist"}) {
					t.Fatal("unexpected command or secret in arguments")
				}
				return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileVaultValidationProcess$", "--", "--filevault-validation-fixture", tc.mode)
			}
			valid, err := validateFileVaultRecoveryKey(ctx, key, factory)
			if valid != tc.valid || (err != nil) != tc.fail {
				t.Fatal("incorrect validation result", valid, err)
			}
			if err != nil && !errors.Is(err, ErrUnavailable) {
				t.Fatal("process details escaped the validator")
			}
			if !bytes.Equal(key, []byte(fixtureRecoveryKey)) {
				t.Fatal("validator changed the caller's recovery key")
			}
		})
	}
}

func TestFileVaultValidationRejectsUntrustedInputBeforeExecution(t *testing.T) {
	factory := func(context.Context, string, ...string) *exec.Cmd {
		t.Fatal("invalid input reached execution")
		return nil
	}
	for _, input := range []string{"", strings.ToLower(fixtureRecoveryKey), fixtureRecoveryKey + "\n", fixtureRecoveryKey[:28], strings.ReplaceAll(fixtureRecoveryKey, "A", "<"), strings.ReplaceAll(fixtureRecoveryKey, "-", " ")} {
		if valid, err := validateFileVaultRecoveryKey(t.Context(), []byte(input), factory); valid || !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid key accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if valid, err := validateFileVaultRecoveryKey(ctx, []byte(fixtureRecoveryKey), factory); valid || !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled check reached execution")
	}
}
