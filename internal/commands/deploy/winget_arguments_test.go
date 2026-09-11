package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	openuem "github.com/open-uem/nats"
)

func TestWinGetExactArguments(t *testing.T) {
	for _, operation := range []string{"install", "upgrade", "uninstall"} {
		t.Run(operation, func(t *testing.T) {
			action := openuem.DeployAction{PackageId: "Vendor.Product;$(echo)'&`", PackageVersion: "1.2 beta;&'$(echo)`"}
			args, err := winGetArguments(operation, action)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{operation, "--id", action.PackageId, "--exact", "--source", "winget", "--scope", "machine", "--silent", "--disable-interactivity", "--accept-source-agreements"}
			if operation != "uninstall" {
				want = append(want, "--accept-package-agreements")
			}
			want = append(want, "--version", action.PackageVersion)
			if !reflect.DeepEqual(args, want) {
				t.Fatalf("arguments = %#v", args)
			}
		})
	}
	args, err := winGetArguments("uninstall", openuem.DeployAction{PackageId: "Vendor.Product"})
	if err != nil || args[len(args)-1] != "--all-versions" {
		t.Fatalf("unpinned removal = %v, %v", args, err)
	}
}

func TestWinGetRejectsAmbiguousInputBeforeLocatingOrRunning(t *testing.T) {
	for _, id := range []string{"", "single", "Vendor.", ".Product", "Vendor..Product", "--id.Product", "Vendor.Product --all", "Vendor.Product\n", "Vendor.Product/extra", "Vendor.Product\\extra", "Vendor.Product\x00", "Vendor.Product\xff", "Vendor." + strings.Repeat("a", 33), strings.Repeat("a.", 8) + "a"} {
		_, _, err := executeWinGet(context.Background(), "install", openuem.DeployAction{PackageId: id}, func() (string, error) { t.Fatal("located invalid request"); return "", nil }, nil)
		if !errors.Is(err, errWinGetArguments) {
			t.Fatalf("accepted identifier %q: %v", id, err)
		}
	}
	for _, version := range []string{"--all", " 1", "1 ", "1\n2", "1/2", "1\x00", strings.Repeat("1", 129)} {
		if _, err := winGetArguments("install", openuem.DeployAction{PackageId: "Vendor.Product", PackageVersion: version}); err == nil {
			t.Fatalf("accepted version %q", version)
		}
	}
	if _, err := winGetArguments("search", openuem.DeployAction{PackageId: "Vendor.Product"}); err == nil {
		t.Fatal("accepted unsupported operation")
	}
}

func TestWinGetReportsNonzeroAndUncertainResults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  winGetProcessResult
		err     error
		message string
	}{
		{"installer failure", winGetProcessResult{Started: true, ExitCode: 1603}, nil, "0x00000643"},
		{"no update is not detection", winGetProcessResult{Started: true, ExitCode: 0x8A15002B}, nil, "0x8A15002B"},
		{"not found is not detection", winGetProcessResult{Started: true, ExitCode: 0x8A150014}, nil, "0x8A150014"},
		{"startup", winGetProcessResult{}, errors.New("private path"), "could not start"},
		{"cancelled", winGetProcessResult{Started: true}, context.Canceled, "verify device state"},
		{"invalid runner success", winGetProcessResult{}, nil, "could not start"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, err := executeWinGet(context.Background(), "install", openuem.DeployAction{PackageId: "Vendor.Product"}, func() (string, error) { return "fixture.exe", nil }, func(context.Context, string, []string) (winGetProcessResult, error) { return tc.result, tc.err })
			if err == nil || !strings.Contains(stderr, tc.message) || strings.Contains(stderr, "private path") {
				t.Fatalf("result = %q, %v", stderr, err)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatal("lost error cause")
			}
		})
	}
	stdout, stderr, err := executeWinGet(context.Background(), "install", openuem.DeployAction{PackageId: "Vendor.Product"}, func() (string, error) { return "fixture.exe", nil }, func(context.Context, string, []string) (winGetProcessResult, error) {
		return winGetProcessResult{Started: true, Stdout: "done", Stderr: "warning", Truncated: true}, nil
	})
	if err != nil || stderr != "" || !strings.Contains(stdout, "warning") || !strings.Contains(stdout, "truncated") {
		t.Fatalf("zero exit = %q, %q, %v", stdout, stderr, err)
	}
}

func TestWinGetCancellationPreventsQueuedExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		_, _, err := executeWinGet(ctx, "install", openuem.DeployAction{PackageId: "Vendor.Product"}, func() (string, error) { return "fixture.exe", nil }, func(ctx context.Context, _ string, _ []string) (winGetProcessResult, error) {
			close(started)
			<-ctx.Done()
			return winGetProcessResult{Started: true}, ctx.Err()
		})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not start")
	}
	queued, cancelQueued := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelQueued()
	_, _, err := executeWinGet(queued, "uninstall", openuem.DeployAction{PackageId: "Vendor.Product"}, func() (string, error) { t.Fatal("queued cancelled request located executable"); return "", nil }, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued result = %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled execution did not release gate")
	}
	_, _, err = executeWinGet(ctx, "install", openuem.DeployAction{PackageId: "Vendor.Product"}, func() (string, error) { t.Fatal("pre-cancelled request located executable"); return "", nil }, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestWinGetOutputRemainsBoundedWhileDraining(t *testing.T) {
	var output boundedWinGetOutput
	chunk := []byte(strings.Repeat("x", 10000))
	for range 100 {
		n, err := output.Write(chunk)
		if n != len(chunk) || err != nil {
			t.Fatalf("write = %d, %v", n, err)
		}
	}
	if len(output.data) != winGetOutputLimit || !output.truncated {
		t.Fatalf("retained %d bytes, truncated %v", len(output.data), output.truncated)
	}
}

func TestWinGetLocatorUsesMatchingArchitectureAndNumericVersion(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"Microsoft.DesktopAppInstaller_1.9.0.0_x64__8wekyb3d8bbwe", "Microsoft.DesktopAppInstaller_1.10.0.0_x64__8wekyb3d8bbwe", "Microsoft.DesktopAppInstaller_9.0.0.0_arm64__8wekyb3d8bbwe", "Microsoft.DesktopAppInstaller_99.0.0.0_x64__foreign", "Microsoft.DesktopAppInstaller_invalid_x64__8wekyb3d8bbwe"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "winget.exe"), []byte("owned inert fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for arch, version := range map[string]string{"x64": "1.10.0.0", "arm64": "9.0.0.0"} {
		path, err := locateWinGetIn(root, arch)
		if err != nil || path != filepath.Join(root, "Microsoft.DesktopAppInstaller_"+version+"_"+arch+"__8wekyb3d8bbwe", "winget.exe") {
			t.Fatalf("%s: %q, %v", arch, path, err)
		}
	}
	for _, tc := range []struct{ root, arch string }{{root, "386"}, {filepath.Join(root, "missing"), "x64"}, {t.TempDir(), "arm64"}} {
		if _, err := locateWinGetIn(tc.root, tc.arch); err == nil {
			t.Fatal("accepted unavailable executable")
		}
	}
}
