//go:build darwin

package macsecurity

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

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
