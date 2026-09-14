//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInstalledPayloadRequiresExactBytesAndProtectedNativePaths(t *testing.T) {
	if runtime.GOOS == "darwin" && !nativeInstallerAvailable() {
		t.Skip("native ACL support unavailable")
	}
	name := "Applications/NetBird.app/Contents/MacOS/netbird"
	data := []byte("owned inert installed payload")
	files := map[string]installedFile{name: {size: int64(len(data)), hash: sha256.Sum256(data), executable: true}}
	for _, kind := range []string{"exact", "bytes", "missing", "symlink", "linked-parent", "hardlink", "permissions", "parent-permissions", "not-executable"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0755); err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "bytes":
				must(os.WriteFile(path, []byte("owned different installation"), 0755))
			case "missing":
				must(os.Remove(path))
			case "symlink":
				must(os.Rename(path, path+"-moved"))
				must(os.Symlink(path+"-moved", path))
			case "linked-parent":
				must(os.Rename(filepath.Dir(path), filepath.Dir(path)+"-moved"))
				must(os.Symlink(filepath.Dir(path)+"-moved", filepath.Dir(path)))
			case "hardlink":
				must(os.Link(path, path+"-linked"))
			case "permissions":
				must(os.Chmod(path, 0777))
			case "parent-permissions":
				must(os.Chmod(filepath.Dir(path), 0777))
			case "not-executable":
				must(os.Chmod(path, 0644))
			}
			err := verifyInstalledFiles(t.Context(), root, files, uint32(os.Geteuid()))
			if (err == nil) != (kind == "exact") {
				t.Fatal("native installed-state verification mismatch", kind, err)
			}
		})
	}
	root := t.TempDir()
	if _, err := installedPath(t.Context(), root, name, uint32(os.Geteuid()), true); err != nil {
		t.Fatal("an absent client was not a valid target")
	}
}

func TestNativeInstallerProcessHasCleanEnvironmentAndBoundedCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NB_SETUP_KEY", "owned-private-key")
	t.Setenv("HTTPS_PROXY", "https://never-contact.example.test")
	for _, mode := range []string{"environment", "stderr-overflow", "nonzero", "wait"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if mode == "wait" {
				ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
			}
			err := runNativeInstaller(ctx, executable, []string{"-test.run=^TestNativeInspectionHelper$", "--", "--netbird-inspection-fixture", mode})
			wantSuccess := mode == "environment" || mode == "stderr-overflow"
			if (err == nil) != wantSuccess {
				t.Fatal("native process outcome mismatch", mode, err)
			}
			if err != nil && strings.Contains(err.Error(), "private") {
				t.Fatal("private process diagnostics escaped")
			}
		})
	}
}

func TestNativeInstallationRequiresProtectedVendorCLILink(t *testing.T) {
	if runtime.GOOS == "darwin" && !nativeInstallerAvailable() {
		t.Skip("native ACL support unavailable")
	}
	for _, kind := range []string{"exact", "missing", "missing-parent", "other-link", "relative-link", "regular-file", "directory", "linked-parent", "writable-parent"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "usr/local/bin/netbird")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			if kind != "missing-parent" {
				must(os.MkdirAll(filepath.Dir(path), 0755))
			}
			switch kind {
			case "exact":
				must(os.Symlink("/Applications/NetBird.app/Contents/MacOS/netbird", path))
			case "other-link":
				must(os.Symlink("/opt/homebrew/bin/netbird", path))
			case "relative-link":
				must(os.Symlink("../../../Applications/NetBird.app/Contents/MacOS/netbird", path))
			case "regular-file":
				must(os.WriteFile(path, []byte("owned inert other installation"), 0755))
			case "directory":
				must(os.Mkdir(path, 0755))
			case "linked-parent":
				must(os.Rename(filepath.Dir(path), filepath.Dir(path)+"-moved"))
				must(os.Symlink(filepath.Dir(path)+"-moved", filepath.Dir(path)))
			case "writable-parent":
				must(os.Chmod(filepath.Dir(path), 0777))
			}
			for _, preflight := range []bool{true, false} {
				err := nativeCLIPath(t.Context(), root, uint32(os.Geteuid()), preflight)
				want := kind == "exact" || preflight && (kind == "missing" || kind == "missing-parent")
				if (err == nil) != want {
					t.Fatal("CLI installation path mismatch", kind, preflight, err)
				}
			}
		})
	}
}

func TestNativeInstallerWaitHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--netbird-install-wait-fixture" {
		return
	}
	if syscall.Getpgrp() != os.Getpid() || os.WriteFile(os.Args[len(os.Args)-1], []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
		os.Exit(2)
	}
	time.Sleep(time.Minute)
	os.Exit(3)
}

func TestNativeInstallerCancellationJoinsStartedProcess(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidfile := filepath.Join(t.TempDir(), "owned-process")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runNativeInstaller(ctx, executable, []string{"-test.run=^TestNativeInstallerWaitHelper$", "--", "--netbird-install-wait-fixture", pidfile})
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	limit := time.NewTimer(5 * time.Second)
	defer limit.Stop()
	pid := 0
	for pid == 0 {
		select {
		case <-ticker.C:
			if data, err := os.ReadFile(pidfile); err == nil {
				pid, _ = strconv.Atoi(string(data))
			}
		case <-limit.C:
			t.Fatal("owned process did not start")
		}
	}
	cancel()
	if err = <-done; err == nil {
		t.Fatal("cancelled native process succeeded")
	}
	if err = syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatal("native process was not joined", err)
	}
}
