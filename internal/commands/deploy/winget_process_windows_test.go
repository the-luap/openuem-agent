//go:build windows

package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This fixture only launches copies of the test executable. It never locates
// WinGet, installs a package, changes a service, or touches an enrolled device.
func TestWinGetProcessHelper(t *testing.T) {
	marker := slices.Index(os.Args, "--winget-owned-fixture")
	if marker < 0 {
		return
	}
	args := os.Args[marker+1:]
	if len(args) == 0 {
		os.Exit(90)
	}
	switch args[0] {
	case "echo":
		_ = json.NewEncoder(os.Stdout).Encode(args[1:])
		_, _ = fmt.Fprint(os.Stderr, "diagnostic")
	case "exit":
		windows.ExitProcess(0x8A15002B)
	case "output":
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("o", 1<<20))
		_, _ = fmt.Fprint(os.Stderr, strings.Repeat("e", 1<<20))
	case "child":
		time.Sleep(30 * time.Second)
	case "tree", "unfinished-child":
		executable, err := os.Executable()
		if err != nil {
			os.Exit(91)
		}
		child := exec.Command(executable, winGetHelperArgs("child")...)
		if err = child.Start(); err != nil {
			os.Exit(92)
		}
		data, _ := json.Marshal([]uint32{uint32(os.Getpid()), uint32(child.Process.Pid)})
		if err = os.WriteFile(args[1], data, 0600); err != nil {
			_ = child.Process.Kill()
			os.Exit(93)
		}
		if args[0] == "tree" {
			_ = child.Wait()
		}
	default:
		os.Exit(94)
	}
	os.Exit(0)
}

func winGetHelperArgs(args ...string) []string {
	return append([]string{"-test.run=^TestWinGetProcessHelper$", "--", "--winget-owned-fixture"}, args...)
}

func TestNativeWindowsWinGetPreservesArgumentsAndExitCode(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	want := []string{"", "Vendor.Product;$(echo)'&`", "1.2 beta", `quoted"value`, `ends with slash\`, "--all", "Grüße"}
	result, err := runWinGetProcess(ctx, executable, winGetHelperArgs(append([]string{"echo"}, want...)...))
	if err != nil || !result.Started || result.ExitCode != 0 || result.Stderr != "diagnostic" {
		t.Fatalf("echo = %+v, %v", result, err)
	}
	var got []string
	if err = json.Unmarshal([]byte(result.Stdout), &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments = %#v, %v", got, err)
	}
	result, err = runWinGetProcess(ctx, executable, winGetHelperArgs("exit"))
	if err != nil || !result.Started || result.ExitCode != 0x8A15002B {
		t.Fatalf("exit = %+v, %v", result, err)
	}
}

func TestNativeWindowsWinGetBoundsOutputAndRejectsStartup(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := runWinGetProcess(ctx, executable, winGetHelperArgs("output"))
	if err != nil || !result.Started || result.ExitCode != 0 || !result.Truncated || len(result.Stdout) != winGetOutputLimit || len(result.Stderr) != winGetOutputLimit {
		t.Fatalf("output lengths %d/%d, truncated %v, exit %d, error %v", len(result.Stdout), len(result.Stderr), result.Truncated, result.ExitCode, err)
	}
	for _, path := range []string{"relative.exe", filepath.Join(t.TempDir(), "missing.exe")} {
		result, err = runWinGetProcess(ctx, path, nil)
		if err == nil || result.Started {
			t.Fatalf("startup %q = %+v, %v", path, result, err)
		}
	}
	cancel()
	result, err = runWinGetProcess(ctx, executable, winGetHelperArgs("echo"))
	if !errors.Is(err, context.Canceled) || result.Started {
		t.Fatalf("pre-cancelled = %+v, %v", result, err)
	}
}

func TestNativeWindowsWinGetCancellationJoinsOwnedTree(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	unrelated := exec.Command(executable, winGetHelperArgs("child")...)
	if err = unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unrelated.Process.Kill(); _ = unrelated.Wait() })
	unrelatedHandle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(unrelated.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(unrelatedHandle)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pidFile := filepath.Join(t.TempDir(), "owned-processes.json")
	type outcome struct {
		result winGetProcessResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := runWinGetProcess(ctx, executable, winGetHelperArgs("tree", pidFile))
		done <- outcome{result, err}
	}()
	handles := openWinGetFixtureProcesses(t, pidFile, 2)
	cancel()
	select {
	case completed := <-done:
		if !completed.result.Started || !errors.Is(completed.err, context.Canceled) {
			t.Fatalf("cancellation = %+v, %v", completed.result, completed.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled process or pipe readers were not joined")
	}
	assertWinGetFixtureExited(t, handles)
	if status, err := windows.WaitForSingleObject(unrelatedHandle, 0); err != nil || status != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("unrelated process affected: %d, %v", status, err)
	}
}

func TestNativeWindowsWinGetRejectsUnfinishedChildWithClosedOutput(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pidFile := filepath.Join(t.TempDir(), "owned-processes.json")
	done := make(chan error, 1)
	go func() {
		_, err := runWinGetProcess(ctx, executable, winGetHelperArgs("unfinished-child", pidFile))
		done <- err
	}()
	handles := openWinGetFixtureProcesses(t, pidFile, 1)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "unfinished") {
			t.Fatalf("unfinished child = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unfinished child exceeded drain deadline")
	}
	assertWinGetFixtureExited(t, handles)
}

func openWinGetFixtureProcesses(t *testing.T, path string, count int) []windows.Handle {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		var pids []uint32
		if err == nil && json.Unmarshal(data, &pids) == nil && len(pids) == 2 {
			var handles []windows.Handle
			for _, pid := range pids[len(pids)-count:] {
				handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = windows.CloseHandle(handle) })
				handles = append(handles, handle)
			}
			return handles
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owned child did not publish its process IDs")
	return nil
}

func assertWinGetFixtureExited(t *testing.T, handles []windows.Handle) {
	t.Helper()
	for _, handle := range handles {
		if status, err := windows.WaitForSingleObject(handle, 2000); err != nil || status != windows.WAIT_OBJECT_0 {
			t.Fatalf("owned process still running: %d, %v", status, err)
		}
	}
}
