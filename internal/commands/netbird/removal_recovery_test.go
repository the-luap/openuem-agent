package netbird

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func ownedRecoveryService(t *testing.T) (*DurableService, netbirdcommand.Command, netbirdcommand.ControlRequest, netbirdcommand.Command) {
	t.Helper()
	s, original, _ := ownedRemovalService(t)
	j := s.journal
	if ok, _, err := j.BeginRemoval(original, time.Now(), j.State(time.Now()).Revision); err != nil || !ok {
		t.Fatal(err)
	}
	if _, err := j.Finish(original, "unconfirmed", time.Now()); err != nil {
		t.Fatal(err)
	}
	hash, _ := original.Digest()
	releaseID := uuid.NewString()
	if err := j.Release(original.RequestID, hash, releaseID, time.Now()); err != nil {
		t.Fatal(err)
	}
	c := original
	c.Version, c.Operation, c.RequestID, c.Removal = netbirdcommand.RemovalRecoveryVersion, "recover-removal", uuid.NewString(), packageapi.Removal{}
	c.RemovalRecovery = netbirdcommand.RemovalRecovery{
		Original: netbirdcommand.RemovalRecoveryReference{RequestID: original.RequestID, CommandHash: hash, Revision: original.Revision, ReleaseID: releaseID, Removal: original.Removal},
		Mode:     "manifest", JournalRevision: j.State(time.Now()).Revision, StateDigest: strings.Repeat("d", 64),
	}
	s.removalRecovery = &removalRecoveryOwner{
		inspect: func(context.Context, string, packageapi.Removal) (string, error) {
			return c.RemovalRecovery.StateDigest, nil
		},
		prepare: func(context.Context, string, packageapi.Removal, string) (nativeRemoval, error) {
			return &ownedNativeInstallation{run: func(context.Context) error { return nil }}, nil
		},
	}
	s.executor.recoverRemoval = s.acquireRemovalRecovery
	at := time.Now().UTC()
	query := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalRecoveryInspectionVersion, Identity: c.Identity, RequestID: uuid.NewString(), Kind: "removal-recovery-state", RemovalRecoveryOriginal: c.RemovalRecovery.Original, IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.RemovalRecoveryInspectionLifetime)}
	return s, c, query, original
}

func advanceRecoveryJournal(t *testing.T, s *DurableService, c netbirdcommand.Command, complete bool) {
	t.Helper()
	other := connectionAfterInstallation(c)
	other.Removal, other.RemovalRecovery = packageapi.Removal{}, netbirdcommand.RemovalRecovery{}
	if ok, _, err := s.journal.Begin(other, time.Now()); err != nil || !ok {
		t.Fatal(err)
	}
	if complete {
		if _, err := s.journal.Finish(other, "completed", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecoveryServiceInspectionRequiresPairedOwnerReleasedOriginalAndStableJournal(t *testing.T) {
	for _, kind := range []string{"ok", "no-owner", "no-inspector", "no-planner", "no-executor", "busy", "missing", "wrong-release", "wrong-identity", "expired", "identity-deadline", "pending", "changed-journal", "query-failed", "invalid-digest", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s, c, query, _ := ownedRecoveryService(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			s.removalRecovery.inspect = func(_ context.Context, id string, d packageapi.Removal) (string, error) {
				calls++
				if id != c.RemovalRecovery.Original.RequestID || d != c.RemovalRecovery.Original.Removal {
					t.Error("inspection changed original manifest binding")
				}
				switch kind {
				case "query-failed":
					return "", ErrActionUnconfirmed
				case "invalid-digest":
					return "invalid", nil
				case "cancelled":
					cancel()
				case "changed-journal":
					advanceRecoveryJournal(t, s, c, true)
				}
				return c.RemovalRecovery.StateDigest, nil
			}
			switch kind {
			case "no-owner":
				s.removalRecovery = nil
			case "no-inspector":
				s.removalRecovery.inspect = nil
			case "no-planner":
				s.removalRecovery.prepare = nil
			case "no-executor":
				s.executor.recoverRemoval = nil
			case "busy":
				s.executor.mu.Lock()
				defer s.executor.mu.Unlock()
			case "missing":
				query.RemovalRecoveryOriginal.RequestID = uuid.NewString()
			case "wrong-release":
				query.RemovalRecoveryOriginal.ReleaseID = uuid.NewString()
			case "wrong-identity":
				query.CertificateHash = strings.Repeat("e", 64)
			case "expired":
				query.IssuedAt = query.IssuedAt.Add(-time.Hour)
				query.ExpiresAt = query.ExpiresAt.Add(-time.Hour)
			case "identity-deadline":
				s.expires = query.ExpiresAt.Add(-time.Nanosecond)
			case "pending":
				advanceRecoveryJournal(t, s, c, false)
			}
			before := s.journal.State(time.Now())
			r := s.removalRecoveryState(ctx, query)
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
			if want == "ok" && (r.State != before || r.RemovalRecovery != c.RemovalRecovery) {
				t.Fatal("current review not bound to original release")
			}
			if kind != "changed-journal" && s.journal.State(time.Now()) != before {
				t.Fatal("read-only inspection changed journal")
			}
			wantCalls := 0
			switch kind {
			case "ok", "changed-journal", "query-failed", "invalid-digest", "cancelled":
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatal("native inspection crossed admission guards", calls, wantCalls)
			}
		})
	}
}

func TestRecoveryBrokerRetainsSeparateResultAndReplaysWithoutNativeAcquisition(t *testing.T) {
	s, c, query, original := ownedRecoveryService(t)
	var plans, runs atomic.Int32
	native := &ownedNativeInstallation{run: func(ctx context.Context) error {
		runs.Add(1)
		if r, err := s.journal.Lookup(c); err != nil || r == nil || r.Status != "unconfirmed" {
			t.Error("recovery mutated before durable attempt", err)
		}
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(c.ExpiresAt) {
			t.Error("recovery lost deadline")
		}
		return nil
	}}
	s.removalRecovery.prepare = func(_ context.Context, id string, d packageapi.Removal, digest string) (nativeRemoval, error) {
		plans.Add(1)
		if id != original.RequestID || d != original.Removal || digest != c.RemovalRecovery.StateDigest {
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
	if r := sendServiceControl(t, nc, query); r.Outcome != "ok" || r.RemovalRecovery != c.RemovalRecovery {
		t.Fatal("broker omitted recovery review")
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
			t.Fatal("recovery receipt", err)
		}
		if i == 0 {
			first = r
			s.removalRecovery = nil
			s.executor.recoverRemoval = nil
		} else if first != r {
			t.Fatal("replay changed recovery result")
		}
	}
	if plans.Load() != 1 || runs.Load() != 1 || native.closed.Load() != 1 {
		t.Fatal("replay touched native stage")
	}
	ref := c.RemovalRecovery.Original
	r, releaseID, err := s.journal.Query(ref.RequestID, ref.CommandHash)
	if err != nil || r == nil || r.Status != "unconfirmed" || !r.Matches(original) || releaseID != ref.ReleaseID {
		t.Fatal("recovery rewrote original removal")
	}
	// Direct retained-result lookup also survives expiry, without a native owner.
	s.executor.now = func() time.Time { return c.ExpiresAt.Add(time.Hour) }
	if r, err := s.executor.Execute(t.Context(), data); err != nil || r != first {
		t.Fatal("retained recovery required execution capability", err)
	}
}

func TestRecoveryServiceRejectsStaleAcquisitionAndClosesEveryRejectedOwner(t *testing.T) {
	for _, kind := range []string{"stale-review", "wrong-release", "journal", "cancelled", "failed-plan", "nil-plan", "closed-service", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			s, c, _, _ := ownedRecoveryService(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			plans, runs, closes := 0, 0, 0
			s.removalRecovery.prepare = func(context.Context, string, packageapi.Removal, string) (nativeRemoval, error) {
				plans++
				native := &recoveryTestOwner{run: func(context.Context) error { runs++; return nil }, close: func() error {
					closes++
					if kind == "cleanup" {
						return ErrActionUnconfirmed
					}
					return nil
				}}
				switch kind {
				case "journal":
					advanceRecoveryJournal(t, s, c, true)
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
				c.RemovalRecovery.JournalRevision = strings.Repeat("e", 64)
			case "wrong-release":
				c.RemovalRecovery.Original.ReleaseID = uuid.NewString()
			}
			data, _ := netbirdcommand.Encode(c)
			r, err := s.executor.Execute(ctx, data)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "cleanup" {
				if r.Status != "unconfirmed" || plans != 1 || runs != 1 || closes != 1 {
					t.Fatal("cleanup failure confirmed recovery")
				}
				return
			}
			if r.Status != "rejected" || runs != 0 {
				t.Fatal("rejected recovery executed")
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
				t.Fatal("rejected recovery acquired attempt", err)
			}
		})
	}
}

type recoveryTestOwner struct {
	run   func(context.Context) error
	close func() error
}

func (r *recoveryTestOwner) Run(ctx context.Context) error { return r.run(ctx) }
func (r *recoveryTestOwner) Close() error                  { return r.close() }

func TestRecoveryNeverFallsThroughToExistingRunners(t *testing.T) {
	s, c, query, _ := ownedRecoveryService(t)
	s.removalRecovery = nil
	s.executor.recoverRemoval = nil
	s.executor.run = func(context.Context, netbirdcommand.Command) error {
		t.Error("connection runner acquired recovery")
		return nil
	}
	s.executor.remove = func(context.Context, netbirdcommand.Command) (*nativePackageLease, error) {
		t.Error("fresh removal acquired recovery")
		return nil, nil
	}
	s.executor.install = s.executor.remove
	nc := serviceBroker(t)
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	if r := sendServiceControl(t, nc, query); r.Outcome != "unavailable" {
		t.Fatal("unconfigured service advertised recovery")
	}
	before := s.journal.State(time.Now())
	data, _ := netbirdcommand.Encode(c)
	if r, err := s.executor.Execute(t.Context(), data); err != nil || r.Status != "rejected" {
		t.Fatal("unconfigured recovery accepted", err)
	}
	if s.journal.State(time.Now()) != before {
		t.Fatal("unconfigured recovery changed journal")
	}
}

func TestRecoveryCancellationJoinsOwnerBeforeResultAndRetainsBarrier(t *testing.T) {
	s, c, _, _ := ownedRecoveryService(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var runs, closes atomic.Int32
	s.removalRecovery.prepare = func(context.Context, string, packageapi.Removal, string) (nativeRemoval, error) {
		return &recoveryTestOwner{run: func(ctx context.Context) error {
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
		t.Fatal("recovery did not start")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("recovery did not join native owner")
	case <-time.After(20 * time.Millisecond):
	}
	if s.journal.State(time.Now()).Status != "busy" || closes.Load() != 0 {
		t.Fatal("unjoined recovery released barrier")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recovery did not join")
	}
	if executionError != nil || result.Status != "unconfirmed" || closes.Load() != 1 {
		t.Fatal("cancelled recovery lost uncertainty", executionError)
	}
	if r, err := s.executor.Execute(t.Context(), data); err != nil || r != result || runs.Load() != 1 || closes.Load() != 1 {
		t.Fatal("uncertain recovery repeated", err)
	}
	next := c
	next.RequestID = uuid.NewString()
	next.RemovalRecovery.JournalRevision = s.journal.State(time.Now()).Revision
	body, _ := netbirdcommand.Encode(next)
	if r, err := s.executor.Execute(t.Context(), body); err != nil || r.Status != "rejected" || runs.Load() != 1 {
		t.Fatal("original release bypassed latest uncertainty", err)
	}
}
