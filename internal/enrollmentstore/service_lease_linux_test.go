package enrollmentstore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLinuxServiceLeaseProcessFixture(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires owned root Linux fixture")
	}
	directory := os.Getenv("OPENUEM_TEST_SERVICE_LEASE_DIRECTORY")
	if directory == "" {
		t.Skip("isolated subprocess fixture")
	}
	lease, err := AcquireServiceLease(directory)
	if os.Getenv("OPENUEM_TEST_SERVICE_LEASE_MODE") == "busy" {
		if lease != nil || !errors.Is(err, ErrServiceBusy) {
			t.Fatal("another process obtained service ownership", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	fmt.Println("service-lease-held")
	var input [1]byte
	_, _ = os.Stdin.Read(input[:])
}

func TestLinuxServiceLeaseExcludesProcessesAndSurvivesOwnerExit(t *testing.T) {
	directory := linuxServiceLeaseDirectory(t)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireServiceLease(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := lease.Validate(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(filepath.Join(directory, serviceLeaseName))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxServiceLeaseProcessFixture$")
	cmd.Env = append(os.Environ(), "OPENUEM_TEST_SERVICE_LEASE_DIRECTORY="+directory, "OPENUEM_TEST_SERVICE_LEASE_MODE=busy")
	if err := cmd.Run(); err != nil {
		t.Fatal("kernel lease did not exclude another process", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Validate(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed lease remained authoritative", err)
	}
	cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxServiceLeaseProcessFixture$")
	cmd.Env = append(os.Environ(), "OPENUEM_TEST_SERVICE_LEASE_DIRECTORY="+directory, "OPENUEM_TEST_SERVICE_LEASE_MODE=hold")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "service-lease-held" {
		t.Fatal("child did not acquire the lease", err)
	}
	if other, err := AcquireServiceLease(directory); other != nil || !errors.Is(err, ErrServiceBusy) {
		t.Fatal("child lease permitted a second owner", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	again, err := AcquireServiceLease(directory)
	if err != nil {
		t.Fatal("process exit did not release kernel ownership", err)
	}
	defer again.Close()
	after, err := os.Lstat(filepath.Join(directory, serviceLeaseName))
	if err != nil || !os.SameFile(before, after) || after.Size() != 0 {
		t.Fatal("lease recovery replaced persistent evidence", err)
	}
}

func TestLinuxServiceLeaseRejectsUntrustedOrReplacedNativeObjects(t *testing.T) {
	for _, mode := range []string{"directory permissions", "symlink", "hardlink", "contents", "file permissions", "foreign owner"} {
		t.Run(mode, func(t *testing.T) {
			directory := linuxServiceLeaseDirectory(t)
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, serviceLeaseName)

			switch mode {
			case "directory permissions":
				if err := os.Chmod(directory, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(directory, "target"), path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.WriteFile(filepath.Join(directory, "target"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(filepath.Join(directory, "target"), path); err != nil {
					t.Fatal(err)
				}
			case "contents":
				if err := os.WriteFile(path, []byte("retained data"), 0600); err != nil {
					t.Fatal(err)
				}
			case "file permissions":
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "foreign owner":
				if err := os.Chown(directory, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			}
			if lease, err := AcquireServiceLease(directory); lease != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("untrusted service lock was repaired or accepted", err)
			}
		})
	}
	directory := linuxServiceLeaseDirectory(t)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireServiceLease(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	path := filepath.Join(directory, serviceLeaseName)
	if err := os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := lease.Validate(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("replaced lock preserved stale ownership", err)
	}
}

// The Linux runner supplies a private root-owned TMPDIR, outside shared /tmp.
// Tests never relax the production ancestor policy or change host directories.
func linuxServiceLeaseDirectory(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires owned root Linux fixture")
	}
	directory, err := os.MkdirTemp(os.TempDir(), "uem-lease-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestLinuxServiceLeaseRejectsUnsafeAncestryAndPreservesExistingData(t *testing.T) {
	for _, kind := range []string{"shared parent", "sticky parent", "foreign parent", "symlink parent", "symlink directory", "setgid directory", "fifo", "socket", "root path", "relative path", "unclean path"} {
		t.Run(kind, func(t *testing.T) {
			base := linuxServiceLeaseDirectory(t)
			parent := filepath.Join(base, "parent")
			directory := filepath.Join(parent, "identity")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, serviceLeaseName)
			switch kind {
			case "shared parent":
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			case "sticky parent":
				if err := os.Chmod(parent, os.ModeSticky|0777); err != nil {
					t.Fatal(err)
				}
			case "foreign parent":
				if err := os.Chown(parent, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "symlink parent", "symlink directory":
				target := parent
				if kind == "symlink directory" {
					target = directory
				}
				if err := os.Rename(target, target+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target+".retained", target); err != nil {
					t.Fatal(err)
				}
			case "setgid directory":
				if err := os.Chmod(directory, os.ModeSetgid|0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "socket":
				listener, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
			case "root path":
				directory = "/"
			case "relative path":
				directory = "identity"
			case "unclean path":
				directory += "/../identity"
			}
			if lease, err := AcquireServiceLease(directory); lease != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("unsafe namespace accepted", err)
			}
			if kind == "fifo" {
				if stat, err := os.Lstat(path); err != nil || stat.Mode()&os.ModeNamedPipe == 0 {
					t.Fatal("foreign object was removed", err)
				}
			}
		})
	}
}

func TestLinuxServiceLeaseInvalidatesChangedNamespaceWithoutUnlinkingEvidence(t *testing.T) {
	for _, kind := range []string{"ancestor replacement", "directory replacement", "ancestor permissions", "directory permissions", "lock permissions", "lock contents", "lock hardlink"} {
		t.Run(kind, func(t *testing.T) {
			base := linuxServiceLeaseDirectory(t)
			parent := filepath.Join(base, "parent")
			directory := filepath.Join(parent, "identity")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			lease, err := AcquireServiceLease(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			path := filepath.Join(directory, serviceLeaseName)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			retained := path
			switch kind {
			case "ancestor replacement", "directory replacement":
				target := parent
				if kind == "directory replacement" {
					target = directory
				}
				if err := os.Rename(target, target+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
				retained = filepath.Join(directory+".retained", serviceLeaseName)
				if kind == "ancestor replacement" {
					retained = filepath.Join(parent+".retained", "identity", serviceLeaseName)
				}
			case "ancestor permissions":
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			case "directory permissions":
				if err := os.Chmod(directory, 0755); err != nil {
					t.Fatal(err)
				}
			case "lock permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "lock contents":
				if err := os.WriteFile(path, []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "lock hardlink":
				if err := os.Link(path, path+".linked"); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(lease.Validate(), ErrUnavailable) || !errors.Is(lease.ValidateDirectory(directory), ErrUnavailable) {
				t.Fatal("changed namespace remained authoritative")
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(retained)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("close replaced or removed evidence", err)
			}
		})
	}
}

func TestLinuxServiceLeaseConcurrentOwnersAndJoinedClose(t *testing.T) {
	directory := linuxServiceLeaseDirectory(t)
	lease, err := AcquireServiceLease(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	var joined sync.WaitGroup
	for range 12 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			other, err := AcquireServiceLease(directory)
			if other != nil {
				other.Close()
			}
			if other != nil || !errors.Is(err, ErrServiceBusy) {
				t.Error("competing handle acquired ownership", err)
			}
		}()
	}
	joined.Wait()
	if !errors.Is(lease.ValidateDirectory(filepath.Join(directory, "other")), ErrUnavailable) {
		t.Fatal("lease changed installation")
	}
	for range 12 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			for range 100 {
				if err := lease.Validate(); err != nil && !errors.Is(err, ErrUnavailable) {
					t.Error(err)
				}
			}
		}()
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	joined.Wait()
	next, err := AcquireServiceLease(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
}

func TestLinuxServiceLeaseRejectsUnprivilegedCaller(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("separate owned unprivileged Linux fixture")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if lease, err := AcquireServiceLease(directory); lease != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("unprivileged process acquired a native service lease", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected acquisition changed the installation", err)
	}
}
