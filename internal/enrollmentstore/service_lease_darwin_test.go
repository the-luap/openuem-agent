package enrollmentstore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMacServiceLeaseProcessFixture(t *testing.T) {
	directory := os.Getenv("OPENUEM_TEST_SERVICE_LEASE_DIRECTORY")
	if directory == "" {
		t.Skip("isolated subprocess fixture")
	}
	lease, err := acquireServiceLease(directory, uint32(os.Geteuid()))
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

func TestMacServiceLeaseExcludesProcessesAndSurvivesOwnerExit(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	lease, err := acquireServiceLease(directory, uint32(os.Geteuid()))
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
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMacServiceLeaseProcessFixture$")
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
	cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMacServiceLeaseProcessFixture$")
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
	if other, err := acquireServiceLease(directory, uint32(os.Geteuid())); other != nil || !errors.Is(err, ErrServiceBusy) {
		t.Fatal("child lease permitted a second owner", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	again, err := acquireServiceLease(directory, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal("process exit did not release kernel ownership", err)
	}
	defer again.Close()
	after, err := os.Lstat(filepath.Join(directory, serviceLeaseName))
	if err != nil || !os.SameFile(before, after) || after.Size() != 0 {
		t.Fatal("lease recovery replaced persistent evidence", err)
	}
}

func TestMacServiceLeaseRejectsUntrustedOrReplacedNativeObjects(t *testing.T) {
	for _, mode := range []string{"directory permissions", "symlink", "hardlink", "contents", "file permissions", "foreign owner"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, serviceLeaseName)
			owner := uint32(os.Geteuid())
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
				owner++
			}
			if lease, err := acquireServiceLease(directory, owner); lease != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("untrusted service lock was repaired or accepted", err)
			}
		})
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	lease, err := acquireServiceLease(directory, uint32(os.Geteuid()))
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
