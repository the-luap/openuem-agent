package netbirdjournal

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJournalLeaseSubprocess(t *testing.T) {
	directory := os.Getenv("OPENUEM_TEST_NETBIRD_JOURNAL")
	if directory == "" {
		return
	}
	c := testCommand()
	j, err := Open(directory, strings.Repeat("b", 64), c.Identity, testBoot())
	if os.Getenv("OPENUEM_TEST_NETBIRD_EXPECT_OPEN") == "true" {
		if err != nil {
			t.Fatal("released process lease could not be acquired", err)
		}
		j.Close()
	} else if err == nil {
		j.Close()
		t.Fatal("other process acquired an owned journal")
	}
}

func TestJournalLeaseExcludesAnotherProcessUntilClose(t *testing.T) {
	c := testCommand()
	directory := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, directory, c, testBoot())
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(expected string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, executable, "-test.run=^TestJournalLeaseSubprocess$", "-test.count=1")
		child.Env = append(os.Environ(), "OPENUEM_TEST_NETBIRD_JOURNAL="+directory, "OPENUEM_TEST_NETBIRD_EXPECT_OPEN="+expected)
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("owned journal lease child failed: %v\n%s", err, output)
		}
	}
	run("false")
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	run("true")
}
