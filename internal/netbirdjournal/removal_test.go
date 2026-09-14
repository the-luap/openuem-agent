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

func removalTestCommand() netbirdcommand.Command {
	c := installationTestCommand()
	c.Version, c.Operation, c.Package = netbirdcommand.RemovalVersion, "uninstall", packageapi.Package{}
	c.Removal = packageapi.Removal{Schema: 1, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", StateDigest: strings.Repeat("f", 64)}
	c.ExpiresAt = c.IssuedAt.Add(netbirdcommand.RemovalLifetime)
	return c
}

func TestRemovalJournalRequiresReviewedStateAndPreservesCrashBarrier(t *testing.T) {
	c := removalTestCommand()
	path := filepath.Join(t.TempDir(), "journal")
	boot := testBoot()
	j := openTest(t, path, c, boot)
	if _, _, err := j.Begin(c, c.IssuedAt); !errors.Is(err, ErrConflict) {
		t.Fatal("ordinary admission bypassed removal inspection", err)
	}
	state := j.State(c.IssuedAt)
	if _, _, err := j.BeginPrepared(c, c.IssuedAt, state.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("installation preparation admitted removal", err)
	}
	if ok, _, err := j.BeginRemoval(c, c.IssuedAt, state.Revision); err != nil || !ok {
		t.Fatal(err)
	}
	j.Close()
	j = openTest(t, path, c, boot)
	hash, _ := c.Digest()
	resolution := uuid.NewString()
	if err := j.Release(c.RequestID, hash, resolution, c.IssuedAt.Add(time.Second)); !errors.Is(err, ErrPending) {
		t.Fatal("same-boot orphaned removal was released", err)
	}
	j.Close()
	boot.ID = uuid.NewString()
	j = openTest(t, path, c, boot)
	next := c
	next.RequestID = uuid.NewString()
	if admitted, _, err := j.BeginRemoval(next, c.IssuedAt.Add(time.Second), j.State(c.IssuedAt.Add(time.Second)).Revision); err == nil || admitted {
		t.Fatal("reboot silently retried removal", err)
	}
	if err := j.Release(c.RequestID, hash, resolution, c.IssuedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := j.BeginRemoval(next, c.IssuedAt.Add(time.Second), j.State(c.IssuedAt.Add(time.Second)).Revision); err != nil || !ok {
		t.Fatal(err)
	}
	if _, err := j.Finish(next, "completed", c.IssuedAt.Add(3*time.Minute)); err != nil {
		t.Fatal("removal was restricted to connection deadline", err)
	}
}

func TestRemovalWithdrawalPermanentlyPreventsNativeAdmission(t *testing.T) {
	c := removalTestCommand()
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	hash, _ := c.Digest()
	at := time.Now().UTC()
	control := netbirdcommand.ControlRequest{Version: netbirdcommand.RecoveryVersion, Identity: c.Identity, RequestID: uuid.NewString(), Kind: "withdraw", ReferenceID: c.RequestID, CommandHash: hash, Revision: c.Revision, Operation: "uninstall", IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.ControlLifetime)}
	data, _ := netbirdcommand.EncodeControl(control)
	proof, err := j.Control(t.Context(), data)
	if err != nil || !proof.Matches(control) || proof.Receipt.Status != "withdrawn" {
		t.Fatal(err)
	}
	j.Close()
	j = openTest(t, path, c, testBoot())
	if ok, r, err := j.BeginRemoval(c, time.Now(), j.State(time.Now()).Revision); err != nil || ok || r == nil || *r != proof.Receipt {
		t.Fatal("withdrawn removal was admitted", err)
	}
	changed := c
	changed.Removal.StateDigest = strings.Repeat("e", 64)
	if _, _, err := j.BeginRemoval(changed, time.Now(), j.State(time.Now()).Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("withdrawal ignored changed native state", err)
	}
}

func TestRemovalCannotBeRestoredUnderLegacyIdentity(t *testing.T) {
	for _, kind := range []string{"start", "withdrawal"} {
		t.Run(kind, func(t *testing.T) {
			c := removalTestCommand()
			c.Individual, c.CertificateHash = false, ""
			path := filepath.Join(t.TempDir(), "journal")
			j := openTest(t, path, c, testBoot())
			if kind == "start" {
				s := start{RequestID: c.RequestID, DeviceID: c.DeviceID, Revision: c.Revision, CommandHash: strings.Repeat("e", 64), Operation: "uninstall", IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, RecordedAt: c.IssuedAt, Boot: testBoot()}
				if err := j.files.create(recordName(1, "start"), s); err != nil {
					t.Fatal(err)
				}
			} else {
				w := withdrawal{Index: 1, Receipt: netbirdcommand.Receipt{Version: 1, RequestID: c.RequestID, DeviceID: c.DeviceID, Revision: c.Revision, CommandHash: strings.Repeat("e", 64), Operation: "uninstall", Status: "withdrawn"}, WithdrawalID: uuid.NewString(), RecordedAt: c.IssuedAt, Boot: testBoot()}
				if err := j.files.create(withdrawalName(1), w); err != nil {
					t.Fatal(err)
				}
			}
			j.Close()
			if reopened, err := Open(path, strings.Repeat("b", 64), c.Identity, testBoot()); err == nil {
				reopened.Close()
				t.Fatal("legacy journal accepted native removal evidence")
			}
		})
	}
}

func TestJournalAloneDoesNotAdvertiseNativeRemovalInspection(t *testing.T) {
	c := removalTestCommand()
	j := openTest(t, filepath.Join(t.TempDir(), "journal"), c, testBoot())
	at := time.Now().UTC()
	query := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalInspectionVersion, Identity: c.Identity, RequestID: uuid.NewString(), Kind: "removal-state", IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.RemovalInspectionLifetime)}
	data, _ := netbirdcommand.EncodeControl(query)
	r, err := j.Control(t.Context(), data)
	if err != nil || !r.Matches(query) || r.Outcome != "unavailable" {
		t.Fatal("bare journal advertised native package ownership", err)
	}
}
