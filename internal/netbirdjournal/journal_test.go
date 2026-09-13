package netbirdjournal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
)

func testCommand() netbirdcommand.Command {
	at := time.Now().UTC().Truncate(time.Microsecond)
	return netbirdcommand.Command{Version: 1, Identity: netbirdcommand.Identity{DeviceID: "owned-device", TenantID: 1, SiteID: 2}, RequestID: uuid.NewString(), Revision: strings.Repeat("a", 64), Operation: "switchprofile", Profile: "Office, Berlin", ManagementURL: "https://private-management.example.test", IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.Lifetime)}
}
func testBoot() Boot { return Boot{Platform: "linux", ID: "90000000-0000-4000-8000-000000000001"} }
func openTest(t *testing.T, path string, c netbirdcommand.Command, boot Boot) *Journal {
	t.Helper()
	j, err := Open(path, strings.Repeat("b", 64), c.Identity, boot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	return j
}
func beginTest(t *testing.T, j *Journal, c netbirdcommand.Command) {
	t.Helper()
	ok, receipt, err := j.Begin(c, c.IssuedAt)
	if err != nil || !ok || receipt != nil {
		t.Fatal("attempt was not admitted exactly once", ok, receipt, err)
	}
}

func TestJournalDurableResultReplayAndPrivateMetadata(t *testing.T) {
	c := testCommand()
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	beginTest(t, j, c)
	r, err := j.Finish(c, "completed", c.IssuedAt.Add(time.Second))
	if err != nil || r.Status != "completed" || !r.Matches(c) {
		t.Fatal("result was not persisted", err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openTest(t, path, c, testBoot())
	for _, now := range []time.Time{c.IssuedAt.Add(time.Second), c.ExpiresAt.Add(time.Hour)} {
		admitted, r, err := j.Begin(c, now)
		if err != nil || admitted || r == nil || r.Status != "completed" || !r.Matches(c) {
			t.Fatal("replay repeated or lost completed evidence", err)
		}
	}
	changed := c
	changed.Profile = "other"
	if _, _, err = j.Begin(changed, c.IssuedAt.Add(time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatal("reused UUID changed command", err)
	}
	files, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		body, err := os.ReadFile(filepath.Join(path, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{c.ManagementURL, c.Profile} {
			if strings.Contains(string(body), secret) {
				t.Fatal("journal retained command configuration")
			}
		}
	}
}

func TestJournalCrashNeedsLaterBootAndExplicitRelease(t *testing.T) {
	c := testCommand()
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	beginTest(t, j, c)
	j.Close()
	j = openTest(t, path, c, testBoot())
	admitted, r, err := j.Begin(c, c.IssuedAt.Add(time.Second))
	if err != nil || admitted || r.Status != "unconfirmed" {
		t.Fatal("crash replay lost uncertainty", err)
	}
	next := c
	next.RequestID = uuid.NewString()
	if _, _, err = j.Begin(next, c.IssuedAt.Add(time.Second)); !errors.Is(err, ErrPending) {
		t.Fatal("crash allowed another command", err)
	}
	if _, err = j.Finish(c, "completed", c.IssuedAt.Add(time.Second)); !errors.Is(err, ErrPending) {
		t.Fatal("recovery invented completion", err)
	}
	digest, _ := c.Digest()
	releaseID := uuid.NewString()
	if err = j.Release(c.RequestID, digest, releaseID, c.IssuedAt.Add(time.Second)); !errors.Is(err, ErrPending) {
		t.Fatal("same-boot orphan was released", err)
	}
	j.Close()
	later := testBoot()
	later.ID = uuid.NewString()
	j = openTest(t, path, c, later)
	if _, _, err = j.Begin(next, c.IssuedAt.Add(time.Second)); !errors.Is(err, ErrPending) {
		t.Fatal("reboot silently released uncertainty", err)
	}
	if err = j.Release(c.RequestID, digest, releaseID, c.IssuedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = j.Release(c.RequestID, digest, releaseID, c.IssuedAt.Add(time.Second)); err != nil {
		t.Fatal("idempotent release changed", err)
	}
	if err = j.Release(c.RequestID, digest, uuid.NewString(), c.IssuedAt.Add(time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatal("release evidence rewritten", err)
	}
	admitted, _, err = j.Begin(next, c.IssuedAt.Add(time.Second))
	if err != nil || !admitted {
		t.Fatal("reviewed reboot did not permit new work", err)
	}
	old, err := j.Lookup(c)
	if err != nil || old.Status != "unconfirmed" {
		t.Fatal("release rewrote historical result", err)
	}
	j.Close()
	j = openTest(t, path, c, later)
	old, err = j.Lookup(c)
	if err != nil || old.Status != "unconfirmed" {
		t.Fatal("release evidence did not survive restart", err)
	}
}

func TestJournalJoinedFailureExpiryAndClockRollback(t *testing.T) {
	c := testCommand()
	j := openTest(t, filepath.Join(t.TempDir(), "journal"), c, testBoot())
	if admitted, _, err := j.Begin(c, c.ExpiresAt); admitted || !errors.Is(err, netbirdcommand.ErrInvalid) {
		t.Fatal("expired command admitted", err)
	}
	beginTest(t, j, c)
	r, err := j.Finish(c, "completed", c.ExpiresAt)
	if err != nil || r.Status != "unconfirmed" {
		t.Fatal("late completion became success", err)
	}
	digest, _ := c.Digest()
	if err = j.Release(c.RequestID, digest, uuid.NewString(), c.ExpiresAt); err != nil {
		t.Fatal("joined failed command could not be reviewed", err)
	}
	next := testCommand()
	if _, _, err = j.Begin(next, c.IssuedAt); !errors.Is(err, ErrUnavailable) {
		t.Fatal("clock rollback bypassed retained time", err)
	}
}

func TestJournalConcurrentAdmissionAndProcessLease(t *testing.T) {
	c := testCommand()
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	if duplicate, err := Open(path, strings.Repeat("b", 64), c.Identity, testBoot()); err == nil {
		duplicate.Close()
		t.Fatal("second journal owner acquired same process lease")
	}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	failures := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _, err := j.Begin(c, c.IssuedAt)
			if ok {
				admitted.Add(1)
			}
			failures <- err
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if admitted.Load() != 1 {
		t.Fatal("concurrent request executed more than once")
	}
	digest, _ := c.Digest()
	if err := j.Release(c.RequestID, digest, uuid.NewString(), c.IssuedAt); !errors.Is(err, ErrPending) {
		t.Fatal("active command released", err)
	}
}

func TestJournalRejectsPartialRestoreAndCorruptRecords(t *testing.T) {
	for _, mutation := range []string{"anchor", "start", "result", "corrupt", "gap", "unknown", "oversize"} {
		t.Run(mutation, func(t *testing.T) {
			c := testCommand()
			path := filepath.Join(t.TempDir(), "journal")
			j := openTest(t, path, c, testBoot())
			beginTest(t, j, c)
			if _, err := j.Finish(c, "completed", c.IssuedAt.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			j.Close()
			switch mutation {
			case "anchor":
				if err := os.Remove(filepath.Join(path, "anchor.json")); err != nil {
					t.Fatal(err)
				}
			case "start":
				if err := os.Remove(filepath.Join(path, "0001-start.json")); err != nil {
					t.Fatal(err)
				}
			case "result":
				if err := os.Remove(filepath.Join(path, "0001-result.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(filepath.Join(path, "0001-start.json"), []byte(`{"RequestID":null}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "gap":
				if err := os.Rename(filepath.Join(path, "0001-start.json"), filepath.Join(path, "0002-start.json")); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(path, ".pending-owned"), []byte("incomplete"), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(filepath.Join(path, "0001-start.json"), []byte(strings.Repeat("x", maxRecord+1)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			restored, err := Open(path, strings.Repeat("b", 64), c.Identity, testBoot())
			if mutation == "result" {
				if err != nil {
					t.Fatal(err)
				}
				defer restored.Close()
				ok, r, err := restored.Begin(c, c.IssuedAt.Add(time.Second))
				if err != nil || ok || r.Status != "unconfirmed" {
					t.Fatal("missing result enabled replay", err)
				}
			} else if err == nil {
				restored.Close()
				t.Fatal("partial/corrupt journal accepted")
			}
		})
	}
}

func TestJournalFailedPublicationPoisonsOwnerAndNeverClaimsSuccess(t *testing.T) {
	c := testCommand()
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	beginTest(t, j, c)
	if err := os.WriteFile(filepath.Join(path, "0001-result.json"), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	if r, err := j.Finish(c, "completed", c.IssuedAt.Add(time.Second)); err == nil || r != nil {
		t.Fatal("failed result publication claimed completion")
	}
	if _, err := j.Lookup(c); !errors.Is(err, ErrUnavailable) {
		t.Fatal("poisoned journal still returned evidence", err)
	}
	j.Close()
	if restored, err := Open(path, strings.Repeat("b", 64), c.Identity, testBoot()); err == nil {
		restored.Close()
		t.Fatal("failed publication became an empty journal")
	}
}

func TestJournalBindsScopeInstallationAndRenewableIdentity(t *testing.T) {
	c := testCommand()
	c.Individual = true
	c.DeviceID = uuid.NewString()
	c.CertificateHash = strings.Repeat("c", 64)
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	beginTest(t, j, c)
	j.Close()
	other := c.Identity
	other.SiteID++
	if j, err := Open(path, strings.Repeat("b", 64), other, testBoot()); err == nil {
		j.Close()
		t.Fatal("foreign scope opened journal")
	}
	if j, err := Open(path, strings.Repeat("d", 64), c.Identity, testBoot()); err == nil {
		j.Close()
		t.Fatal("another installation opened journal")
	}
	renewed := c
	renewed.CertificateHash = strings.Repeat("e", 64)
	j = openTest(t, path, renewed, testBoot())
	if _, err := j.Lookup(c); !errors.Is(err, ErrConflict) {
		t.Fatal("old certificate authorized live journal", err)
	}
	next := renewed
	next.RequestID = uuid.NewString()
	if _, _, err := j.Begin(next, c.IssuedAt.Add(time.Second)); !errors.Is(err, ErrPending) {
		t.Fatal("renewal erased unresolved execution", err)
	}
}

func TestNativeBootEvidenceStable(t *testing.T) {
	first, err := ReadBoot()
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReadBoot()
	if err != nil || !first.Valid() || second != first || second.After(first) {
		t.Fatal("native boot identity was not stable", err)
	}
}
