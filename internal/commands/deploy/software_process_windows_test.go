//go:build windows

package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"golang.org/x/sys/windows"
)

func softwareProcessPlan() enrollment.SoftwarePlan {
	return enrollment.SoftwarePlan{Kind: "windows-exe", Operation: "install", Identifier: "OpenUEM.OwnedFixture", Version: "1.2.3", Architecture: "amd64", MinimumOS: "10.0.19045",
		Artifact: enrollment.SoftwareArtifact{URL: "https://example.invalid/fixture.exe", Format: "exe", SHA256: strings.Repeat("a", 64)}, Arguments: []string{"/quiet"},
		Detection: enrollment.SoftwareDetection{Kind: "uninstall-key", UninstallKey: "OpenUEM.OwnedFixture", RegistryView: "64", Version: "1.2.3"}, SuccessCodes: []uint32{0}, RebootCodes: []uint32{3010}}
}

func TestNativeWindowsSoftwareEXEArgumentsAndProcessFacts(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	plan := softwareProcessPlan()
	want := []string{"", "literal ; $() & %PATH%", `ends in slash\`, `quoted"value`, "Unicode 🐈"}
	plan.Arguments = winGetHelperArgs(append([]string{"echo"}, want...)...)
	path, command, err := softwareCommand(plan, executable, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	raw, err := runWindowsProcess(ctx, path, command)
	var got []string
	if err != nil || json.Unmarshal([]byte(raw.Stdout), &got) != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("approved EXE arguments changed", got, err)
	}
	plan.Arguments = winGetHelperArgs("exit")
	result, err := RunSoftwareProcess(ctx, plan, executable)
	if err != nil || !result.Started || result.ExitCode == nil || *result.ExitCode != 0x8A15002B {
		t.Fatal("32-bit exit code lost", result, err)
	}
	plan.Arguments = winGetHelperArgs("output")
	result, err = RunSoftwareProcess(ctx, plan, executable)
	if err != nil || !result.Started || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatal("bounded diagnostics prevented process completion", result, err)
	}
	for _, invalid := range []string{"relative.exe", filepath.Join(t.TempDir(), "missing.exe"), `\\server\share\installer.exe`, `C:\a\..\installer.exe`, `C:\installer.msi`} {
		result, err = RunSoftwareProcess(ctx, plan, invalid)
		if !errors.Is(err, ErrSoftwareProcess) || result.Started || result.ExitCode != nil {
			t.Fatal("invalid EXE started", result, err)
		}
	}
	cancel()
	result, err = RunSoftwareProcess(ctx, plan, executable)
	if !errors.Is(err, ErrSoftwareProcess) || result.Started || result.ExitCode != nil {
		t.Fatal("cancelled EXE admitted", result, err)
	}
}

func TestNativeWindowsSoftwareBurnUsesExactPinnedEXE(t *testing.T) {
	plan := softwareProcessPlan()
	plan.Kind = "windows-burn"
	plan.Arguments = []string{"/quiet", "/norestart"}
	plan.Detection.UninstallKey = "{AABBCCDD-0000-4000-8000-000000000001}"
	for _, operation := range []string{"install", "remove"} {
		plan.Operation = operation
		if operation == "remove" {
			plan.Arguments = []string{"/uninstall", "/quiet", "/norestart"}
		}
		if !plan.Valid() {
			t.Fatal("owned Burn contract invalid")
		}
		for _, path := range []string{"", `C:\owned\installer.exe`, `C:\owned\installer.msi`} {
			called := false
			result, err := runSoftwareProcess(t.Context(), plan, path, func(_ context.Context, executable, command string) (winGetProcessResult, error) {
				called = true
				if executable != path || command != windows.ComposeCommandLine(append([]string{path}, plan.Arguments...)) {
					t.Error("explicit Burn changed the pinned executable or fixed arguments")
				}
				return winGetProcessResult{Started: true, ExitCode: 0}, nil
			})
			if path == `C:\owned\installer.exe` {
				if err != nil || !called || !result.Started || result.ExitCode == nil || *result.ExitCode != 0 {
					t.Fatal("explicit Burn did not execute its retained artifact", result, err)
				}
			} else if err == nil || called || result.Started || result.ExitCode != nil {
				t.Fatal("Burn with no pinned EXE reached another adapter")
			}
		}
	}
}

func TestNativeWindowsSoftwareCancellationPreservesUncertainty(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	plan := softwareProcessPlan()
	pidFile := filepath.Join(t.TempDir(), "owned-software-processes.json")
	plan.Arguments = winGetHelperArgs("tree", pidFile)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	type completed struct {
		result SoftwareProcessResult
		err    error
	}
	done := make(chan completed, 1)
	go func() { result, err := RunSoftwareProcess(ctx, plan, executable); done <- completed{result, err} }()
	handles := openWinGetFixtureProcesses(t, pidFile, 2)
	cancel()
	select {
	case value := <-done:
		if !errors.Is(value.err, ErrSoftwareProcess) || !value.result.Started || value.result.ExitCode != nil {
			t.Fatal("interrupted process became completed", value)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("installer process cancellation was not joined")
	}
	assertWinGetFixtureExited(t, handles)
}
