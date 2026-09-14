package netbird

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-agent/internal/netbirdinstall"
)

func ownedStageCleanupService(t *testing.T) (*DurableService, netbirdcommand.Command, netbirdcommand.ControlRequest, netbirdcommand.Command) {
	t.Helper()
	s, c, _, original := ownedRecoveryService(t)
	reference := c.RemovalRecovery.Original
	c.Version, c.Operation, c.RequestID = netbirdcommand.RemovalStageCleanupVersion, "cleanup-removal-stage", uuid.NewString()
	c.RemovalStageCleanup = netbirdcommand.RemovalStageCleanup{Original: netbirdcommand.RemovalStageCleanupReference{RequestID: reference.RequestID, CommandHash: reference.CommandHash, Revision: reference.Revision, ReleaseID: reference.ReleaseID}, Profile: netbirdcommand.RemovalStageCleanupProfile, JournalRevision: c.RemovalRecovery.JournalRevision, StateDigest: strings.Repeat("d", 64), DirectoryCount: 7, ManifestPresent: true, ManifestBytes: 128}
	c.RemovalRecovery = netbirdcommand.RemovalRecovery{}
	c.ExpiresAt = c.IssuedAt.Add(netbirdcommand.RemovalStageCleanupLifetime)
	s.removalStageCleanup = &removalStageCleanupOwner{
		inspect: func(_ context.Context, originalID string) (netbirdinstall.RemovalStageCleanupReview, error) {
			if originalID != c.RemovalStageCleanup.Original.RequestID {
				t.Fatal("inspection changed selected scaffold")
			}
			return removalStageCleanupReview(c.RemovalStageCleanup), nil
		},
		prepare: func(context.Context, string, netbirdinstall.RemovalStageCleanupReview) (nativeRemoval, error) {
			return &ownedNativeInstallation{run: func(context.Context) error { return nil }}, nil
		},
	}
	s.executor.cleanupRemovalStage = s.acquireRemovalStageCleanup
	at := time.Now().UTC()
	query := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalStageCleanupInspectionVersion, Identity: c.Identity, RequestID: uuid.NewString(), Kind: "removal-stage-cleanup-state", RemovalStageCleanupOriginal: c.RemovalStageCleanup.Original, IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.RemovalStageCleanupInspectionLifetime)}
	return s, c, query, original
}

func advanceStageCleanupJournal(t *testing.T, s *DurableService, c netbirdcommand.Command, complete bool) {
	c.RemovalStageCleanup = netbirdcommand.RemovalStageCleanup{}
	advanceRecoveryJournal(t, s, c, complete)
}

func TestStageCleanupServiceInspectionRequiresPairedOwnerReleasedOriginalAndStableJournal(t *testing.T) {
	for _, kind := range []string{"ok", "no-owner", "no-inspector", "no-planner", "no-executor", "busy", "missing", "wrong-release", "wrong-identity", "expired", "identity-deadline", "pending", "changed-journal", "query-failed", "invalid-digest", "invalid-count", "invalid-manifest", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s, c, query, _ := ownedStageCleanupService(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			s.removalStageCleanup.inspect = func(_ context.Context, originalID string) (netbirdinstall.RemovalStageCleanupReview, error) {
				calls++
				switch kind {
				case "query-failed":
					return netbirdinstall.RemovalStageCleanupReview{}, ErrActionUnconfirmed
				case "invalid-digest":
					return netbirdinstall.RemovalStageCleanupReview{StateDigest: "invalid"}, nil
				case "invalid-count":
					v := removalStageCleanupReview(c.RemovalStageCleanup)
					v.DirectoryCount = 0
					return v, nil
				case "invalid-manifest":
					v := removalStageCleanupReview(c.RemovalStageCleanup)
					v.ManifestPresent = false
					return v, nil
				case "cancelled":
					cancel()
				case "changed-journal":
					advanceStageCleanupJournal(t, s, c, true)
				}
				if originalID != c.RemovalStageCleanup.Original.RequestID {
					t.Fatal("inspection changed selected scaffold")
				}
				return removalStageCleanupReview(c.RemovalStageCleanup), nil
			}
			switch kind {
			case "no-owner":
				s.removalStageCleanup = nil
			case "no-inspector":
				s.removalStageCleanup.inspect = nil
			case "no-planner":
				s.removalStageCleanup.prepare = nil
			case "no-executor":
				s.executor.cleanupRemovalStage = nil
			case "busy":
				s.executor.mu.Lock()
				defer s.executor.mu.Unlock()
			case "missing":
				query.RemovalStageCleanupOriginal.RequestID = uuid.NewString()
			case "wrong-release":
				query.RemovalStageCleanupOriginal.ReleaseID = uuid.NewString()
			case "wrong-identity":
				query.CertificateHash = strings.Repeat("e", 64)
			case "expired":
				query.IssuedAt = query.IssuedAt.Add(-time.Hour)
				query.ExpiresAt = query.ExpiresAt.Add(-time.Hour)
			case "identity-deadline":
				s.expires = query.ExpiresAt.Add(-time.Nanosecond)
			case "pending":
				advanceStageCleanupJournal(t, s, c, false)
			}
			before := s.journal.State(time.Now())
			r := s.removalStageCleanupState(ctx, query)
			want := "unavailable"
			switch kind {
			case "ok":
				want = "ok"
			case "missing":
				want = "missing"
			case "wrong-release":
				want = "conflict"
			case "busy", "pending", "changed-journal":
				want = "blocked"
			}
			if !r.Matches(query) || r.Outcome != want {
				t.Fatal(kind, "incorrect inspection outcome", r.Outcome)
			}
			if want == "ok" && (r.State != before || r.RemovalStageCleanup != c.RemovalStageCleanup) {
				t.Fatal("current review not bound to original release")
			}
			if kind != "changed-journal" && s.journal.State(time.Now()) != before {
				t.Fatal("read-only inspection changed journal")
			}
			wantCalls := 0
			switch kind {
			case "ok", "changed-journal", "query-failed", "invalid-digest", "invalid-count", "invalid-manifest", "cancelled":
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatal("native inspection crossed admission guards", calls, wantCalls)
			}
		})
	}
}

func TestStageCleanupBrokerRetainsSeparateResultAndReplaysWithoutNativeAcquisition(t *testing.T) {
	s, c, query, original := ownedStageCleanupService(t)
	var plans, runs atomic.Int32
	native := &ownedNativeInstallation{run: func(ctx context.Context) error {
		runs.Add(1)
		if r, err := s.journal.Lookup(c); err != nil || r == nil || r.Status != "unconfirmed" {
			t.Error("cleanup mutated before durable attempt", err)
		}
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(c.ExpiresAt) {
			t.Error("cleanup lost deadline")
		}
		return nil
	}}
	s.removalStageCleanup.prepare = func(_ context.Context, originalID string, review netbirdinstall.RemovalStageCleanupReview) (nativeRemoval, error) {
		plans.Add(1)
		if originalID != c.RemovalStageCleanup.Original.RequestID || review != removalStageCleanupReview(c.RemovalStageCleanup) {
			t.Error("native preparation changed reviewed original")
		}
		if r, err := s.journal.Lookup(c); err != nil || r != nil {
			t.Error("preparation acquired an attempt")
		}
		return native, nil
	}
	nc := serviceBroker(t)
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	if r := sendServiceControl(t, nc, query); r.Outcome != "ok" || r.RemovalStageCleanup != c.RemovalStageCleanup {
		t.Fatal("broker omitted cleanup review")
	}
	subject, _ := netbirdcommand.Subject(c.DeviceID)
	data, _ := netbirdcommand.Encode(c)
	var first netbirdcommand.Receipt
	for i := 0; i < 2; i++ {
		response, err := nc.Request(subject, data, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		r, err := netbirdcommand.DecodeReceipt(response.Data)
		if err != nil || !r.Matches(c) || r.Status != "completed" {
			t.Fatal("cleanup receipt", err)
		}
		if i == 0 {
			first = r
			s.removalStageCleanup = nil
			s.executor.cleanupRemovalStage = nil
		} else if first != r {
			t.Fatal("replay changed cleanup result")
		}
	}
	if plans.Load() != 1 || runs.Load() != 1 || native.closed.Load() != 1 {
		t.Fatal("replay touched native stage")
	}
	ref := c.RemovalStageCleanup.Original
	r, releaseID, err := s.journal.Query(ref.RequestID, ref.CommandHash)
	if err != nil || r == nil || r.Status != "unconfirmed" || !r.Matches(original) || releaseID != ref.ReleaseID {
		t.Fatal("cleanup rewrote original removal")
	}
	// Direct retained-result lookup also survives expiry, without a native owner.
	s.executor.now = func() time.Time { return c.ExpiresAt.Add(time.Hour) }
	if r, err := s.executor.Execute(t.Context(), data); err != nil || r != first {
		t.Fatal("retained cleanup required execution capability", err)
	}
}

func TestStageCleanupServiceRejectsStaleAcquisitionAndClosesEveryRejectedOwner(t *testing.T) {
	for _, kind := range []string{"stale-review", "wrong-release", "journal", "cancelled", "failed-plan", "nil-plan", "closed-service", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			s, c, _, _ := ownedStageCleanupService(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			plans, runs, closes := 0, 0, 0
			s.removalStageCleanup.prepare = func(context.Context, string, netbirdinstall.RemovalStageCleanupReview) (nativeRemoval, error) {
				plans++
				native := &stageCleanupTestOwner{run: func(context.Context) error { runs++; return nil }, close: func() error {
					closes++
					if kind == "cleanup" {
						return ErrActionUnconfirmed
					}
					return nil
				}}
				switch kind {
				case "journal":
					advanceStageCleanupJournal(t, s, c, true)
				case "cancelled":
					cancel()
				case "failed-plan":
					return native, ErrActionUnconfirmed
				case "nil-plan":
					return nil, nil
				case "closed-service":
					s.cancel()
				}
				return native, nil
			}
			switch kind {
			case "stale-review":
				c.RemovalStageCleanup.JournalRevision = strings.Repeat("e", 64)
			case "wrong-release":
				c.RemovalStageCleanup.Original.ReleaseID = uuid.NewString()
			}
			data, _ := netbirdcommand.Encode(c)
			r, err := s.executor.Execute(ctx, data)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "cleanup" {
				if r.Status != "unconfirmed" || plans != 1 || runs != 1 || closes != 1 {
					t.Fatal("cleanup failure confirmed cleanup")
				}
				return
			}
			if r.Status != "rejected" || runs != 0 {
				t.Fatal("rejected cleanup executed")
			}
			wantPlans, wantCloses := 1, 1
			if kind == "stale-review" || kind == "wrong-release" {
				wantPlans, wantCloses = 0, 0
			}
			if kind == "nil-plan" {
				wantCloses = 0
			}
			if plans != wantPlans || closes != wantCloses {
				t.Fatal("acquisition ownership", plans, closes)
			}
			if receipt, err := s.journal.Lookup(c); err != nil || receipt != nil {
				t.Fatal("rejected cleanup acquired attempt", err)
			}
		})
	}
}

type stageCleanupTestOwner struct {
	run   func(context.Context) error
	close func() error
}

func (r *stageCleanupTestOwner) Run(ctx context.Context) error { return r.run(ctx) }
func (r *stageCleanupTestOwner) Close() error                  { return r.close() }

func TestStageCleanupNeverFallsThroughToExistingRunners(t *testing.T) {
	s, c, query, _ := ownedStageCleanupService(t)
	s.removalStageCleanup = nil
	s.executor.cleanupRemovalStage = nil
	s.executor.run = func(context.Context, netbirdcommand.Command) error {
		t.Error("connection runner acquired cleanup")
		return nil
	}
	s.executor.remove = func(context.Context, netbirdcommand.Command) (*nativePackageLease, error) {
		t.Error("fresh removal acquired cleanup")
		return nil, nil
	}
	s.executor.install = s.executor.remove
	s.executor.recoverRemoval = s.executor.remove
	s.executor.verifyRemovalAbsence = s.executor.remove
	nc := serviceBroker(t)
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	if r := sendServiceControl(t, nc, query); r.Outcome != "unavailable" {
		t.Fatal("unconfigured service advertised cleanup")
	}
	before := s.journal.State(time.Now())
	data, _ := netbirdcommand.Encode(c)
	if r, err := s.executor.Execute(t.Context(), data); err != nil || r.Status != "rejected" {
		t.Fatal("unconfigured cleanup accepted", err)
	}
	if s.journal.State(time.Now()) != before {
		t.Fatal("unconfigured cleanup changed journal")
	}
}

func TestStageCleanupCancellationJoinsOwnerBeforeResultAndRetainsBarrier(t *testing.T) {
	s, c, _, _ := ownedStageCleanupService(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var runs, closes atomic.Int32
	s.removalStageCleanup.prepare = func(context.Context, string, netbirdinstall.RemovalStageCleanupReview) (nativeRemoval, error) {
		return &stageCleanupTestOwner{run: func(ctx context.Context) error {
			runs.Add(1)
			close(entered)
			<-ctx.Done()
			<-release
			return ctx.Err()
		}, close: func() error {
			closes.Add(1)
			if s.journal.State(time.Now()).Status != "busy" {
				t.Error("result persisted before owner close")
			}
			return nil
		}}, nil
	}
	data, _ := netbirdcommand.Encode(c)
	var result netbirdcommand.Receipt
	var executionError error
	go func() { result, executionError = s.executor.Execute(ctx, data); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not start")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("cleanup did not join native owner")
	case <-time.After(20 * time.Millisecond):
	}
	if s.journal.State(time.Now()).Status != "busy" || closes.Load() != 0 {
		t.Fatal("unjoined cleanup released barrier")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not join")
	}
	if executionError != nil || result.Status != "unconfirmed" || closes.Load() != 1 {
		t.Fatal("cancelled cleanup lost uncertainty", executionError)
	}
	if r, err := s.executor.Execute(t.Context(), data); err != nil || r != result || runs.Load() != 1 || closes.Load() != 1 {
		t.Fatal("uncertain cleanup repeated", err)
	}
	next := c
	next.RequestID = uuid.NewString()
	next.RemovalStageCleanup.JournalRevision = s.journal.State(time.Now()).Revision
	body, _ := netbirdcommand.Encode(next)
	if r, err := s.executor.Execute(t.Context(), body); err != nil || r.Status != "rejected" || runs.Load() != 1 {
		t.Fatal("original release bypassed latest uncertainty", err)
	}
}

func TestStageCleanupBrokerWithdrawalNeverAcquiresNativeOwner(t *testing.T) {
	s, c, _, original := ownedStageCleanupService(t)
	s.removalStageCleanup.prepare = func(context.Context, string, netbirdinstall.RemovalStageCleanupReview) (nativeRemoval, error) {
		t.Error("withdrawn cleanup acquired a native owner")
		return nil, ErrActionUnconfirmed
	}
	nc := serviceBroker(t)
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	hash, _ := c.Digest()
	query := netbirdcommand.ControlRequest{Version: netbirdcommand.RecoveryVersion, Identity: c.Identity, RequestID: uuid.NewString(), Kind: "withdraw", ReferenceID: c.RequestID, CommandHash: hash, Revision: c.Revision, Operation: c.Operation, IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.ControlLifetime)}
	proof := sendServiceControl(t, nc, query)
	if proof.Outcome != "ok" || proof.Receipt.Status != "withdrawn" || proof.ReleaseID != query.RequestID {
		t.Fatal("cleanup withdrawal lost exact permanent proof")
	}
	data, _ := netbirdcommand.Encode(c)
	s.executor.now = func() time.Time { return c.ExpiresAt.Add(time.Hour) }
	if receipt, err := s.executor.Execute(t.Context(), data); err != nil || receipt != proof.Receipt {
		t.Fatal("withdrawn cleanup did not retain its result", err)
	}
	ref := c.RemovalStageCleanup.Original
	receipt, release, err := s.journal.Query(ref.RequestID, ref.CommandHash)
	if err != nil || receipt == nil || !receipt.Matches(original) || receipt.Status != "unconfirmed" || release != ref.ReleaseID {
		t.Fatal("withdrawn cleanup changed original uninstall", err)
	}
}
