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

func TestWindowsServiceLeaseProcessFixture(t *testing.T) {
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

func TestWindowsServiceLeaseExcludesProcessesAndPinsProtectedDirectory(t *testing.T) {
	_, directory := windowsFixture(t)
	lease, err := AcquireServiceLease(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := lease.Validate(); err != nil {
		t.Fatal(err)
	}
	// Capture the file ID from the live handle now. Path-based Windows Stat
	// defers ID lookup until SameFile and would compare the new path twice.
	before, err := lease.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsServiceLeaseProcessFixture$")
	cmd.Env = append(os.Environ(), "OPENUEM_TEST_SERVICE_LEASE_DIRECTORY="+directory, "OPENUEM_TEST_SERVICE_LEASE_MODE=busy")
	if err := cmd.Run(); err != nil {
		t.Fatal("native handle admitted another owner", err)
	}
	if err := os.Rename(directory, directory+"-moved"); err == nil {
		t.Fatal("service lease did not pin protected directory")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Validate(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed service lease remained authoritative", err)
	}
	cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsServiceLeaseProcessFixture$")
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
		t.Fatal("child did not acquire service ownership", err)
	}
	if other, err := AcquireServiceLease(directory); other != nil || !errors.Is(err, ErrServiceBusy) {
		t.Fatal("child ownership admitted a competing service", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	again, err := AcquireServiceLease(directory)
	if err != nil {
		t.Fatal("kernel ownership survived process exit", err)
	}
	after, statErr := again.file.Stat()
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
	if statErr != nil || !os.SameFile(before, after) || after.Size() != 0 {
		t.Fatal("lease retry replaced persistent file", statErr)
	}
}

func TestWindowsServiceLeaseRejectsUntrustedOrNonemptyFiles(t *testing.T) {
	for _, mode := range []string{"contents", "hardlink", "directory"} {
		t.Run(mode, func(t *testing.T) {
			_, directory := windowsFixture(t)
			path := filepath.Join(directory, serviceLeaseName)
			if mode == "directory" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				file, err := createSystemFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "contents" {
					if _, err := file.Write([]byte("retained data")); err != nil {
						t.Fatal(err)
					}
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				if mode == "hardlink" {
					if err := os.Link(path, path+"-alias"); err != nil {
						t.Fatal(err)
					}
				}
			}
			if lease, err := AcquireServiceLease(directory); lease != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("untrusted lease object was accepted", err)
			}
		})
	}
}
