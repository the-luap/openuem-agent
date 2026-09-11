package deploy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	openuem "github.com/open-uem/nats"
)

const winGetOutputLimit = 64 << 10
const winGetExecutionLimit = 30 * time.Minute

var winGetGate = make(chan struct{}, 1)
var errWinGetArguments = errors.New("WinGet requires an exact package identifier and a valid optional version")

// Arguments follow the manifest identifier/version grammar and are always
// passed directly to the executable. Shell punctuation remains ordinary data.
func winGetArguments(operation string, action openuem.DeployAction) ([]string, error) {
	id, version := action.PackageId, action.PackageVersion
	validText := func(value string) bool {
		return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 128 &&
			strings.IndexFunc(value, func(c rune) bool { return unicode.IsControl(c) || strings.ContainsRune(`\/:*?"<>|`, c) }) < 0
	}
	if id == "" || strings.HasPrefix(id, "-") || !validText(id) || strings.IndexFunc(id, unicode.IsSpace) >= 0 ||
		!validText(version) || strings.HasPrefix(version, "-") || strings.TrimSpace(version) != version {
		return nil, errWinGetArguments
	}
	parts := strings.Split(id, ".")
	if len(parts) < 2 || len(parts) > 8 {
		return nil, errWinGetArguments
	}
	for _, part := range parts {
		if n := utf8.RuneCountInString(part); n == 0 || n > 32 {
			return nil, errWinGetArguments
		}
	}
	if operation != "install" && operation != "upgrade" && operation != "uninstall" {
		return nil, errWinGetArguments
	}
	args := []string{operation, "--id", id, "--exact", "--source", "winget", "--scope", "machine", "--silent", "--disable-interactivity", "--accept-source-agreements"}
	if operation != "uninstall" {
		args = append(args, "--accept-package-agreements")
	}
	if version != "" {
		args = append(args, "--version", version)
	} else if operation == "uninstall" {
		args = append(args, "--all-versions")
	}
	return args, nil
}

type winGetProcessResult struct {
	Stdout, Stderr string
	ExitCode       uint32
	Started        bool
	Truncated      bool
}

type winGetProcess func(context.Context, string, []string) (winGetProcessResult, error)

type winGetError struct {
	message string
	cause   error
}

func (e *winGetError) Error() string { return e.message }
func (e *winGetError) Unwrap() error { return e.cause }

func executeWinGet(ctx context.Context, operation string, action openuem.DeployAction, locate func() (string, error), run winGetProcess) (string, string, error) {
	args, err := winGetArguments(operation, action)
	if err != nil {
		return "", err.Error(), err
	}
	if ctx == nil {
		return "", "WinGet requires an execution context", errors.New("WinGet requires an execution context")
	}
	ctx, cancel := context.WithTimeout(ctx, winGetExecutionLimit)
	defer cancel()
	select {
	case <-ctx.Done():
		return "", "WinGet request was cancelled before execution", ctx.Err()
	case winGetGate <- struct{}{}:
	}
	defer func() { <-winGetGate }()
	if err = ctx.Err(); err != nil {
		return "", "WinGet request was cancelled before execution", err
	}
	path, err := locate()
	if err != nil {
		failure := &winGetError{message: "A compatible WinGet executable is unavailable", cause: err}
		return "", failure.Error(), failure
	}
	result, err := run(ctx, path, args)
	if err == nil && !result.Started {
		err = errors.New("process did not start")
	}
	if err != nil {
		message := "WinGet could not start"
		if result.Started {
			message = "WinGet execution was interrupted or incomplete; verify device state before retrying"
		}
		failure := &winGetError{message: message, cause: err}
		return result.Stdout, failure.Error(), failure
	}
	if result.ExitCode != 0 {
		message := fmt.Sprintf("WinGet exited with code 0x%08X; the requested device state has not been verified", result.ExitCode)
		failure := &winGetError{message: message}
		return result.Stdout, message, failure
	}
	if result.Truncated {
		result.Stdout += "\n[WinGet output truncated]\n"
	}
	// A zero process exit records command success only. Installer warnings on
	// stderr do not independently prove failure; retain them as output metadata.
	if result.Stderr != "" {
		result.Stdout += "\n" + result.Stderr
	}
	return result.Stdout, "", nil
}

type boundedWinGetOutput struct {
	data      []byte
	truncated bool
}

func (w *boundedWinGetOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := winGetOutputLimit - len(w.data)
	if len(p) > remaining {
		p = p[:remaining]
		w.truncated = true
	}
	w.data = append(w.data, p...)
	return n, nil
}
