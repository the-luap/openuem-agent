package netbirdjournal

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func installationTestCommand() netbirdcommand.Command {
	c := testCommand()
	c.Version, c.Operation, c.Profile, c.ManagementURL = netbirdcommand.InstallationVersion, "install", "", ""
	c.Individual, c.DeviceID, c.CertificateHash = true, uuid.NewString(), strings.Repeat("c", 64)
	c.Package = packageapi.Package{Schema: 1, ApprovalID: uuid.NewString(), TenantID: c.TenantID, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", URL: "https://packages.example.test/netbird.pkg", Size: 1234, SHA256: strings.Repeat("d", 64)}
	c.ExpiresAt = c.IssuedAt.Add(netbirdcommand.InstallationLifetime)
	return c
}

func TestInstallationJournalRetainsLongerNativeDeadline(t *testing.T) {
	c := installationTestCommand()
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	beginTest(t, j, c)
	finished := c.IssuedAt.Add(3 * time.Minute)
	r, err := j.Finish(c, "completed", finished)
	if err != nil || r == nil || r.Status != "completed" {
		t.Fatal("valid native deadline was shortened to a connection deadline", err)
	}
	j.Close()
	j = openTest(t, path, c, testBoot())
	if got, err := j.Lookup(c); err != nil || got == nil || *got != *r {
		t.Fatal("restart rejected a valid installation result", err)
	}
	if admitted, got, err := j.Begin(c, c.ExpiresAt.Add(time.Hour)); err != nil || admitted || got == nil || *got != *r {
		t.Fatal("expired installation repeated", err)
	}
}

func TestInstallationJournalCrashRequiresRebootAndExplicitRelease(t *testing.T) {
	c := installationTestCommand()
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	beginTest(t, j, c)
	j.Close()
	j = openTest(t, path, c, testBoot())
	hash, _ := c.Digest()
	release := uuid.NewString()
	if err := j.Release(c.RequestID, hash, release, c.IssuedAt.Add(time.Second)); !errors.Is(err, ErrPending) {
		t.Fatal("same-boot orphaned installer was released", err)
	}
	j.Close()
	boot := testBoot()
	boot.ID = uuid.NewString()
	j = openTest(t, path, c, boot)
	next := c
	next.RequestID = uuid.NewString()
	if _, _, err := j.Begin(next, c.IssuedAt.Add(time.Second)); !errors.Is(err, ErrPending) {
		t.Fatal("reboot silently retried installer", err)
	}
	if err := j.Release(c.RequestID, hash, release, c.IssuedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if admitted, _, err := j.Begin(next, c.IssuedAt.Add(time.Second)); err != nil || !admitted {
		t.Fatal("explicitly released installer still blocked", err)
	}
}

func TestInstallationJournalRejectsInvalidRetainedLifetimeAndLegacyAnchor(t *testing.T) {
	for _, mode := range []string{"lifetime", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			c := installationTestCommand()
			path := filepath.Join(t.TempDir(), "journal")
			if mode == "legacy" {
				c.Individual, c.CertificateHash = false, ""
			}
			j := openTest(t, path, c, testBoot())
			at := c.ExpiresAt
			if mode == "lifetime" {
				at = at.Add(time.Nanosecond)
			}
			// Deliberately write a malformed retained record in an owned journal.
			record := start{RequestID: c.RequestID, DeviceID: c.DeviceID, Revision: c.Revision, CommandHash: strings.Repeat("e", 64), Operation: "install", IssuedAt: c.IssuedAt, ExpiresAt: at, RecordedAt: c.IssuedAt, Boot: testBoot()}
			if err := j.files.create(recordName(1, "start"), record); err != nil {
				t.Fatal(err)
			}
			j.Close()
			if reopened, err := Open(path, strings.Repeat("b", 64), c.Identity, testBoot()); err == nil {
				reopened.Close()
				t.Fatal("malformed retained installation was accepted")
			}
		})
	}
}
