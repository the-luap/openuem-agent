//go:build windows

package deploy

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"github.com/open-uem/nats/enrollment"
	"golang.org/x/sys/windows"
)

var ErrSoftwareProcess = errors.New("the approved Windows installer process did not complete")

// SoftwareProcessResult exposes process facts only, never native diagnostics,
// private arguments or an installed-state claim. An exit code exists only after
// the process and all owned child/output work completed without a runner error.
type SoftwareProcessResult struct {
	Started  bool
	ExitCode *uint32
}

// RunSoftwareProcess is the low-level process boundary, not command admission.
// Its caller must authenticate the immutable plan, durably record the attempt,
// finish native compatibility/detection checks and retain the verified staged
// artifact through this call. Windows services can outlive a cancelled job.
func RunSoftwareProcess(ctx context.Context, plan enrollment.SoftwarePlan, stagedPath string) (SoftwareProcessResult, error) {
	var result SoftwareProcessResult
	if ctx == nil || ctx.Err() != nil || !plan.Valid() {
		return result, ErrSoftwareProcess
	}
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		return result, ErrSoftwareProcess
	}
	executable, command, err := softwareCommand(plan, stagedPath, filepath.Join(directory, "msiexec.exe"))
	if err != nil {
		return result, ErrSoftwareProcess
	}
	native, err := runWindowsProcess(ctx, executable, command)
	result.Started = native.Started
	if err != nil || !native.Started {
		return result, ErrSoftwareProcess
	}
	code := native.ExitCode
	result.ExitCode = &code
	return result, nil
}

func softwareLocalPath(path, extension string) bool {
	volume := filepath.VolumeName(path)
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(volume) == 2 && volume[1] == ':' && !strings.ContainsAny(path, "\x00\r\n\"") && strings.EqualFold(filepath.Ext(path), extension)
}

func softwareCommand(plan enrollment.SoftwarePlan, stagedPath, msiexec string) (string, string, error) {
	if !plan.Valid() {
		return "", "", ErrSoftwareProcess
	}
	if plan.Kind == "windows-exe" {
		if !softwareLocalPath(stagedPath, ".exe") {
			return "", "", ErrSoftwareProcess
		}
		return stagedPath, windows.ComposeCommandLine(append([]string{stagedPath}, plan.Arguments...)), nil
	}
	if !softwareLocalPath(msiexec, ".exe") {
		return "", "", ErrSoftwareProcess
	}
	var command strings.Builder
	command.WriteString(`"` + msiexec + `"`)
	if plan.Operation == "install" {
		if !softwareLocalPath(stagedPath, ".msi") {
			return "", "", ErrSoftwareProcess
		}
		command.WriteString(` /i "` + stagedPath + `"`)
	} else {
		if stagedPath != "" {
			return "", "", ErrSoftwareProcess
		}
		command.WriteString(` /x ` + plan.Detection.ProductCode)
	}
	command.WriteString(` /qn /norestart ALLUSERS=1 REBOOT=ReallySuppress`)
	keys := make([]string, 0, len(plan.MSIProperties))
	for key := range plan.MSIProperties {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		// The plan rejects quotes/control characters and reserved engine flags.
		// Keep MSI's documented KEY="literal value" syntax in the raw command.
		command.WriteString(` ` + key + `="` + plan.MSIProperties[key] + `"`)
	}
	return msiexec, command.String(), nil
}
