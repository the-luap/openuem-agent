//go:build darwin && cgo

package netbirdinstall

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestRemovalProcessOwnedHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--owned-removal-process" {
		return
	}
	if os.WriteFile(os.Args[len(os.Args)-1], []byte("ready"), 0600) != nil {
		os.Exit(2)
	}
	time.Sleep(time.Minute)
	os.Exit(3)
}

func TestNativeRemovalProcessBindsAuditGenerationAndRunningCode(t *testing.T) {
	if !nativeRemovalProcessAPIAvailable() {
		t.Skip("native audit/code validation requires macOS 11.3 or later")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "owned-process")
	output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		input.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	input.Close()
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("owned binary copy failed")
	}
	if exec.Command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "io.openuem.owned-removal-process", path).Run() != nil {
		t.Fatal("owned ad-hoc code signing failed")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ready := filepath.Join(root, "ready")
	command := exec.CommandContext(ctx, path, "-test.run=^TestRemovalProcessOwnedHelper$", "--", "--owned-removal-process", ready)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	if command.Start() != nil {
		t.Fatal("owned process did not start")
	}
	joined := false
	defer func() {
		if !joined {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("owned process did not become ready")
		}
	}
	pid := command.Process.Pid
	requirement := `identifier "io.openuem.owned-removal-process"`
	proof, err := captureRemovalProcess(ctx, pid, path, requirement)
	if err != nil || proof.PID != uint32(pid) || proof.Audit[5] != uint32(pid) || proof.Audit[7] == 0 || len(proof.CodeHash) != 40 || proof.StartedSeconds == 0 {
		t.Fatal("native audit/code proof missing", err)
	}
	again, err := captureRemovalProcess(ctx, pid, path, requirement)
	if err != nil || !reflect.DeepEqual(proof, again) {
		t.Fatal("stable process identity changed", err)
	}
	if actual, err := nativeRemovalAuditPath(ctx, proof.Audit); err != nil || actual != path {
		t.Fatal("kernel audit token did not resolve its exact executable", err)
	}
	if actual, err := nativeRemovalPIDPath(ctx, pid); err != nil || actual != path {
		t.Fatal("native candidate lookup failed", err)
	}
	if pids, err := nativeRemovalPIDs(ctx); err != nil || !slices.Contains(pids, pid) {
		t.Fatal("bounded native enumeration omitted the owned process", err)
	}
	changed := proof.Audit
	changed[7]++
	if _, err := nativeRemovalAuditPath(ctx, changed); err == nil {
		t.Fatal("different process generation resolved the original process")
	}
	for _, check := range []struct{ path, requirement string }{{path + "-other", requirement}, {path, `identifier "io.other.client"`}, {path, netbirdDeveloperRequirement + ` and identifier "netbird"`}} {
		if _, err := captureRemovalProcess(ctx, pid, check.path, check.requirement); err == nil {
			t.Fatal("foreign path, code identity or publisher was accepted")
		}
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := captureRemovalProcess(cancelled, pid, path, requirement); err == nil {
		t.Fatal("cancelled native capture succeeded")
	}
	// Replace the path while the old image is still running. Dynamic validation
	// must not identify the process using the new file occupying its old path.
	if err := os.Rename(path, path+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("owned replacement file"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := captureRemovalProcess(ctx, pid, path, requirement); err == nil {
		t.Fatal("running old image was accepted as the replacement file")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	joined = true
	if _, err := nativeRemovalAuditPath(ctx, proof.Audit); err == nil {
		t.Fatal("exited process retained live native ownership")
	}
}
