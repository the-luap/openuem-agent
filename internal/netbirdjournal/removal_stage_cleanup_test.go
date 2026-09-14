package netbirdjournal

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func stageCleanupTestCommand(original netbirdcommand.Command, releaseID, journalRevision string) netbirdcommand.Command {
	hash, _ := original.Digest()
	c := original
	c.Version, c.Operation, c.RequestID = netbirdcommand.RemovalStageCleanupVersion, "cleanup-removal-stage", uuid.NewString()
	c.Removal, c.RemovalRecovery = packageapi.Removal{}, netbirdcommand.RemovalRecovery{}
	c.ExpiresAt = c.IssuedAt.Add(netbirdcommand.RemovalStageCleanupLifetime)
	c.RemovalStageCleanup = netbirdcommand.RemovalStageCleanup{
		Original: netbirdcommand.RemovalStageCleanupReference{RequestID: original.RequestID, CommandHash: hash, Revision: original.Revision, ReleaseID: releaseID},
		Profile:  netbirdcommand.RemovalStageCleanupProfile, JournalRevision: journalRevision, StateDigest: strings.Repeat("d", 64), DirectoryCount: 7, ManifestPresent: true, ManifestBytes: 128,
	}
	return c
}

func releasedStageCleanup(t *testing.T) (*Journal, string, netbirdcommand.Command, netbirdcommand.Command) {
	t.Helper()
	j, path, original, recovery := releasedRemoval(t)
	return j, path, original, stageCleanupTestCommand(original, recovery.RemovalRecovery.Original.ReleaseID, recovery.RemovalRecovery.JournalRevision)
}

func TestStageCleanupJournalPreservesOriginalAndNeverRepeatsAttempt(t *testing.T) {
	j, path, original, c := releasedStageCleanup(t)
	ref := c.RemovalStageCleanup.Original
	before, releaseID, err := j.Query(ref.RequestID, ref.CommandHash)
	if err != nil || before == nil {
		t.Fatal(err)
	}
	state, err := j.RemovalStageCleanupState(c.Identity, ref, c.IssuedAt)
	if err != nil || state != j.State(c.IssuedAt) {
		t.Fatal("read-only original proof", err)
	}
	if c.Revision == state.Revision {
		t.Fatal("fixture must distinguish console and journal revisions")
	}
	for _, begin := range []func(netbirdcommand.Command, time.Time, string) (bool, *netbirdcommand.Receipt, error){j.BeginPrepared, j.BeginRemoval, j.BeginRemovalRecovery, j.BeginRemovalAbsence} {
		if ok, _, err := begin(c, c.IssuedAt, state.Revision); err == nil || ok {
			t.Fatal("wrong native admission accepted cleanup")
		}
	}
	if ok, _, err := j.Begin(c, c.IssuedAt); err == nil || ok {
		t.Fatal("ordinary admission bypassed cleanup owner")
	}
	if ok, _, err := j.BeginRemovalStageCleanup(c, c.IssuedAt, state.Revision); err != nil || !ok {
		t.Fatal(err)
	}
	if _, err := j.RemovalStageCleanupState(c.Identity, ref, c.IssuedAt); !errors.Is(err, ErrPending) {
		t.Fatal("active cleanup lost common barrier", err)
	}
	if _, err := j.Finish(c, "completed", c.IssuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	j.Close()
	j = openTest(t, path, c, testBoot())
	for _, at := range []time.Time{c.IssuedAt.Add(time.Minute), c.ExpiresAt.Add(time.Hour)} {
		if ok, r, err := j.BeginRemovalStageCleanup(c, at, state.Revision); err != nil || ok || r == nil || r.Status != "completed" || !r.Matches(c) {
			t.Fatal("replay admitted cleanup", err)
		}
		if ok, r, err := j.Begin(c, at); err != nil || ok || r == nil || r.Status != "completed" {
			t.Fatal("generic replay lost evidence", err)
		}
	}
	after, afterRelease, err := j.Query(ref.RequestID, ref.CommandHash)
	if err != nil || after == nil || *after != *before || afterRelease != releaseID || !after.Matches(original) {
		t.Fatal("cleanup rewrote original evidence", err)
	}
	changed := c
	changed.RemovalStageCleanup.StateDigest = strings.Repeat("e", 64)
	if _, _, err := j.BeginRemovalStageCleanup(changed, c.ExpiresAt.Add(time.Hour), state.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("reused UUID changed cleanup", err)
	}
}

func TestStageCleanupJournalRequiresExactReleasedUnconfirmedRemoval(t *testing.T) {
	for _, kind := range []string{"missing", "withdrawn", "active", "unconfirmed", "completed", "wrong-operation", "released"} {
		t.Run(kind, func(t *testing.T) {
			original := removalTestCommand()
			j := openTest(t, filepath.Join(t.TempDir(), "journal"), original, testBoot())
			releaseID := uuid.NewString()
			if kind == "wrong-operation" {
				original = installationTestCommand()
				original.Identity = j.identity
			}
			if kind == "withdrawn" {
				if r := runControl(t, j, withdrawalRequest(original, "withdraw")); r.Outcome != "ok" {
					t.Fatal("fixture withdrawal")
				}
			} else if kind != "missing" {
				begin := j.BeginRemoval
				if kind == "wrong-operation" {
					begin = j.BeginPrepared
				}
				if ok, _, err := begin(original, original.IssuedAt, j.State(original.IssuedAt).Revision); err != nil || !ok {
					t.Fatal(err)
				}
				if kind != "active" {
					status := "unconfirmed"
					if kind == "completed" {
						status = "completed"
					}
					if _, err := j.Finish(original, status, original.IssuedAt); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "released" || kind == "wrong-operation" {
					hash, _ := original.Digest()
					if err := j.Release(original.RequestID, hash, releaseID, original.IssuedAt); err != nil {
						t.Fatal(err)
					}
				}
			}
			c := stageCleanupTestCommand(original, releaseID, j.State(original.IssuedAt).Revision)
			if kind == "wrong-operation" {
				c.Package = packageapi.Package{}
			}
			before := j.State(original.IssuedAt)
			state, err := j.RemovalStageCleanupState(c.Identity, c.RemovalStageCleanup.Original, c.IssuedAt)
			if kind == "released" {
				if err != nil || state.Status != "ready" {
					t.Fatal(err)
				}
			} else {
				if err == nil || state != (netbirdcommand.State{}) {
					t.Fatal("unauthorized original accepted")
				}
				if ok, _, err := j.BeginRemovalStageCleanup(c, c.IssuedAt, before.Revision); err == nil || ok {
					t.Fatal("unauthorized original admitted")
				}
			}
			if j.State(c.IssuedAt) != before {
				t.Fatal("inspection changed journal")
			}
		})
	}
	for _, change := range []func(*netbirdcommand.Command){
		func(c *netbirdcommand.Command) { c.RemovalStageCleanup.Original.CommandHash = strings.Repeat("e", 64) },
		func(c *netbirdcommand.Command) { c.RemovalStageCleanup.Original.Revision = strings.Repeat("e", 64) },
		func(c *netbirdcommand.Command) { c.RemovalStageCleanup.Original.ReleaseID = uuid.NewString() },
		func(c *netbirdcommand.Command) { c.CertificateHash = strings.Repeat("e", 64) },
		func(c *netbirdcommand.Command) { c.SiteID++ },
		func(c *netbirdcommand.Command) { c.TenantID++ },
		func(c *netbirdcommand.Command) { c.DeviceID = uuid.NewString() },
	} {
		j, _, _, c := releasedStageCleanup(t)
		change(&c)
		if _, err := j.RemovalStageCleanupState(c.Identity, c.RemovalStageCleanup.Original, c.IssuedAt); !errors.Is(err, ErrConflict) {
			t.Fatal("changed original or identity accepted", err)
		}
		if ok, _, err := j.BeginRemovalStageCleanup(c, c.IssuedAt, c.RemovalStageCleanup.JournalRevision); err == nil || ok {
			t.Fatal("changed original admitted")
		}
	}
}

func TestStageCleanupJournalRebootRenewalAndLatestBarrier(t *testing.T) {
	j, path, _, c := releasedStageCleanup(t)
	if ok, _, err := j.BeginRemovalStageCleanup(c, c.IssuedAt, c.RemovalStageCleanup.JournalRevision); err != nil || !ok {
		t.Fatal(err)
	}
	j.Close()
	j = openTest(t, path, c, testBoot())
	hash, _ := c.Digest()
	cleanupRelease := uuid.NewString()
	if err := j.Release(c.RequestID, hash, cleanupRelease, c.IssuedAt); !errors.Is(err, ErrPending) {
		t.Fatal("same-boot orphan released", err)
	}
	j.Close()
	boot := testBoot()
	boot.ID = uuid.NewString()
	renewed := c
	renewed.CertificateHash = strings.Repeat("e", 64)
	j = openTest(t, path, renewed, boot)
	if _, err := j.RemovalStageCleanupState(renewed.Identity, c.RemovalStageCleanup.Original, c.IssuedAt); !errors.Is(err, ErrPending) {
		t.Fatal("old release bypassed latest crash", err)
	}
	if err := j.Release(c.RequestID, hash, cleanupRelease, c.IssuedAt); err != nil {
		t.Fatal(err)
	}
	state, err := j.RemovalStageCleanupState(renewed.Identity, c.RemovalStageCleanup.Original, c.IssuedAt)
	if err != nil {
		t.Fatal("renewal lost original released proof", err)
	}
	next := renewed
	next.RequestID = uuid.NewString()
	if ok, _, err := j.BeginRemovalStageCleanup(next, c.IssuedAt, state.Revision); err == nil || ok {
		t.Fatal("old reviewed journal survived reboot")
	}
	next.RemovalStageCleanup.JournalRevision = state.Revision
	if ok, _, err := j.BeginRemovalStageCleanup(next, c.IssuedAt, state.Revision); err != nil || !ok {
		t.Fatal("fresh review could not verify current scaffold", err)
	}
}

func TestStageCleanupAdmissionSerializesCurrentRevisionAndWithdrawal(t *testing.T) {
	j, _, original, c := releasedStageCleanup(t)
	next := c
	next.RequestID = uuid.NewString()
	var wg sync.WaitGroup
	admissions := make(chan bool, 4)
	for _, command := range []netbirdcommand.Command{c, next, recoveryTestCommand(original, c.RemovalStageCleanup.Original.ReleaseID, c.RemovalStageCleanup.JournalRevision), absenceTestCommand(original, c.RemovalStageCleanup.Original.ReleaseID, c.RemovalStageCleanup.JournalRevision)} {
		wg.Go(func() {
			var ok bool
			if command.Version == netbirdcommand.RemovalRecoveryVersion {
				ok, _, _ = j.BeginRemovalRecovery(command, command.IssuedAt, command.RemovalRecovery.JournalRevision)
			} else if command.Version == netbirdcommand.RemovalAbsenceVersion {
				ok, _, _ = j.BeginRemovalAbsence(command, command.IssuedAt, command.RemovalAbsence.JournalRevision)
			} else {
				ok, _, _ = j.BeginRemovalStageCleanup(command, command.IssuedAt, command.RemovalStageCleanup.JournalRevision)
			}
			admissions <- ok
		})
	}
	wg.Wait()
	close(admissions)
	count := 0
	for ok := range admissions {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatal("concurrent cleanup admission", count)
	}
	j, _, _, c = releasedStageCleanup(t)
	proof := runControl(t, j, withdrawalRequest(c, "withdraw"))
	if proof.Outcome != "ok" || proof.Receipt.Status != "withdrawn" {
		t.Fatal("cleanup withdrawal")
	}
	if ok, r, err := j.BeginRemovalStageCleanup(c, c.ExpiresAt.Add(time.Hour), c.RemovalStageCleanup.JournalRevision); err != nil || ok || r == nil || *r != proof.Receipt {
		t.Fatal("withdrawn cleanup executed", err)
	}
	query := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalStageCleanupInspectionVersion, Identity: c.Identity, RequestID: uuid.NewString(), Kind: "removal-stage-cleanup-state", RemovalStageCleanupOriginal: c.RemovalStageCleanup.Original, IssuedAt: c.IssuedAt, ExpiresAt: c.IssuedAt.Add(netbirdcommand.RemovalStageCleanupInspectionLifetime)}
	data, _ := netbirdcommand.EncodeControl(query)
	if r, err := j.Control(t.Context(), data); err != nil || !r.Matches(query) || r.Outcome != "unavailable" {
		t.Fatal("bare journal advertised native cleanup", err)
	}
}
