//go:build darwin

package macsecurity

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func TestBootSessionIDStableWithinKernelBoot(t *testing.T) {
	first, err := BootSessionID()
	if err != nil {
		t.Fatal("kernel boot identity is unavailable", err)
	}
	parsed, err := uuid.Parse(first)
	if err != nil || parsed == uuid.Nil || parsed.String() != first {
		t.Fatal("noncanonical boot identity")
	}
	second, err := BootSessionID()
	if err != nil || first != second {
		t.Fatal("boot identity changed without a kernel reboot", err)
	}
}

// Both processes are this test binary. The child only waits for EOF on a
// private pipe. No system management command or real device operation runs.
func TestRotationOrphanProcessFixture(t *testing.T) {
	index := slices.Index(os.Args, "--rotation-orphan-fixture")
	if index < 0 {
		return
	}
	if index+2 >= len(os.Args) {
		os.Exit(91)
	}
	mode, directory := os.Args[index+1], os.Args[index+2]
	time.AfterFunc(20*time.Second, func() { os.Exit(92) })
	control := os.NewFile(3, "fixture-control")
	if mode == "child" {
		fmt.Printf("child:%d\n", os.Getpid())
		_, _ = io.Copy(io.Discard, control)
		fmt.Println("stopped")
		os.Exit(0)
	}
	if mode != "parent" {
		os.Exit(93)
	}
	lease, err := acquireFileVaultLease(directory, uint32(os.Geteuid()))
	if err != nil {
		os.Exit(94)
	}
	defer lease.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestRotationOrphanProcessFixture$", "--", "--rotation-orphan-fixture", "child", directory)
	child.ExtraFiles = []*os.File{control}
	child.Stdout = os.Stdout
	if err := child.Run(); err != nil {
		os.Exit(95)
	}
	os.Exit(0)
}

func TestRotationFreeParentLeaseDoesNotProveChildStopped(t *testing.T) {
	dir := privateLeaseDirectory(t)
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer controlRead.Close()
	defer controlWrite.Close()
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outputRead.Close()
	defer outputWrite.Close()
	parent := exec.Command(os.Args[0], "-test.run=^TestRotationOrphanProcessFixture$", "--", "--rotation-orphan-fixture", "parent", dir)
	parent.ExtraFiles, parent.Stdout = []*os.File{controlRead}, outputWrite
	if err = parent.Start(); err != nil {
		t.Fatal(err)
	}
	controlRead.Close()
	outputWrite.Close()
	waited := false
	defer func() {
		if !waited {
			parent.Process.Kill()
			parent.Wait()
		}
		controlWrite.Close()
	}()
	lines := make(chan string, 2)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(outputRead)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	var pid int
	select {
	case line := <-lines:
		if n, err := fmt.Sscanf(line, "child:%d", &pid); err != nil || n != 1 || pid <= 0 {
			t.Fatal("orphan fixture failed to start")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("orphan fixture startup timed out")
	}
	if lease, err := acquireFileVaultLease(dir, uint32(os.Geteuid())); !errors.Is(err, ErrRotationBusy) {
		if lease != nil {
			lease.Close()
		}
		t.Fatal("parent did not hold its lease", err)
	}
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait()
	waited = true
	if err := unix.Kill(pid, 0); err != nil {
		t.Fatal("child did not survive its parent", err)
	}
	lease, err := acquireFileVaultLease(dir, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal("parent death did not release its lease", err)
	}
	defer lease.Close()
	select {
	case <-lines:
		t.Fatal("child stopped before control pipe closed")
	default:
	}
	controlWrite.Close()
	select {
	case line := <-lines:
		if line != "stopped" {
			t.Fatal("child failed controlled shutdown")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child shutdown timed out")
	}
	select {
	case _, open := <-lines:
		if open {
			t.Fatal("unexpected fixture output")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child retained its output descriptor")
	}
}

func privateLeaseDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "rotation-fixture")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestRotationLeaseExcludesConcurrentOwnersAndNeverUnlinks(t *testing.T) {
	dir := privateLeaseDirectory(t)
	lease, err := acquireFileVaultLease(dir, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	before, err := os.Lstat(filepath.Join(dir, rotationLeaseName))
	if err != nil || before.Size() != 0 || before.Mode().Perm() != 0600 {
		t.Fatal("lease file is not empty and private", err)
	}
	var wg sync.WaitGroup
	errorsByOwner := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			other, err := acquireFileVaultLease(dir, uint32(os.Geteuid()))
			if other != nil {
				other.Close()
			}
			errorsByOwner <- err
		})
	}
	wg.Wait()
	close(errorsByOwner)
	for err := range errorsByOwner {
		if !errors.Is(err, ErrRotationBusy) {
			t.Fatal("active lease admitted another owner", err)
		}
	}
	for range 2 {
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.Lstat(filepath.Join(dir, rotationLeaseName))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("lease release removed/replaced the lock file", err)
	}
	second, err := acquireFileVaultLease(dir, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal("closed lease remained locked", err)
	}
	second.Close()
}

func TestRotationLeaseRejectsUntrustedPathsWithoutRepair(t *testing.T) {
	for _, kind := range []string{"directory-symlink", "file-symlink", "hardlink", "shared-directory", "shared-file", "nonempty-file", "fifo", "wrong-owner", "relative"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateLeaseDirectory(t)
			path := filepath.Join(dir, rotationLeaseName)
			owner := uint32(os.Geteuid())
			switch kind {
			case "directory-symlink":
				link := filepath.Join(t.TempDir(), "linked-fixture")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			case "file-symlink", "hardlink":
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, nil, 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "file-symlink" {
					err = os.Symlink(target, path)
				} else {
					err = os.Link(target, path)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "shared-directory":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "shared-file":
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "nonempty-file":
				if err := os.WriteFile(path, []byte("existing state"), 0600); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				owner++
			case "relative":
				dir = "."
			}
			before, _ := os.Lstat(path)
			lease, err := acquireFileVaultLease(dir, owner)
			if lease != nil {
				lease.Close()
			}
			if !errors.Is(err, ErrRotationUnavailable) {
				t.Fatal("untrusted lease object accepted", kind, err)
			}
			if before != nil {
				after, statErr := os.Lstat(path)
				if statErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
					t.Fatal("failed lease repaired existing state", statErr)
				}
			}
		})
	}
	if os.Geteuid() != 0 {
		if _, err := AcquireFileVaultLease(privateLeaseDirectory(t)); !errors.Is(err, ErrRotationUnsupported) {
			t.Fatal("ordinary user acquired production lease", err)
		}
	}
}

func TestRotationLeaseProcessFixture(t *testing.T) {
	index := slices.Index(os.Args, "--rotation-lease-fixture")
	if index < 0 {
		return
	}
	if index+2 >= len(os.Args) || filepath.Base(os.Args[index+1]) != "rotation-fixture" {
		os.Exit(91)
	}
	owner, err := strconv.ParseUint(os.Args[index+2], 10, 32)
	if err != nil {
		os.Exit(92)
	}
	lease, err := acquireFileVaultLease(os.Args[index+1], uint32(owner))
	if err != nil {
		os.Exit(93)
	}
	defer lease.Close()
	fmt.Println("locked")
	// The parent kills this fixture to verify kernel cleanup after a crash.
	time.Sleep(time.Minute)
	os.Exit(94)
}

func TestRotationLeaseProcessExitReleasesWithoutLosingEvidence(t *testing.T) {
	dir := privateLeaseDirectory(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestRotationLeaseProcessFixture$", "--", "--rotation-lease-fixture", dir, strconv.Itoa(os.Geteuid()))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		cmd.Process.Kill()
		if !waited {
			cmd.Wait()
		}
	}()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "locked\n" {
			t.Fatal("fixture did not acquire its lease")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("fixture lease timed out")
	}
	if other, err := acquireFileVaultLease(dir, uint32(os.Geteuid())); !errors.Is(err, ErrRotationBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("second process bypassed live owner", err)
	}
	before, err := os.Lstat(filepath.Join(dir, rotationLeaseName))
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waited = true
	lease, err := acquireFileVaultLease(dir, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal("crashed process retained its lease", err)
	}
	defer lease.Close()
	after, err := os.Lstat(filepath.Join(dir, rotationLeaseName))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("crash recovery replaced persistent state", err)
	}
}
