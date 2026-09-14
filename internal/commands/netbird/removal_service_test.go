package netbird

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func ownedRemovalService(t *testing.T) (*DurableService, netbirdcommand.Command, netbirdcommand.ControlRequest) {
	t.Helper()
	e, j, c, _ := ownedRemoval(t)
	s, err := NewDurableService(t.Context(), j, c.Identity, c.ExpiresAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.executor = e
	s.removal = &removalOwner{inspect: func(context.Context) (packageapi.Removal, bool, error) { return c.Removal, false, nil }, prepare: func(context.Context, string, packageapi.Removal) (nativeRemoval, error) {
		return &ownedNativeInstallation{run: func(context.Context) error { return nil }}, nil
	}}
	s.executor.remove = s.acquireRemoval
	at := time.Now().UTC()
	query := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalInspectionVersion, Identity: c.Identity, RequestID: uuid.NewString(), Kind: "removal-state", IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.RemovalInspectionLifetime)}
	return s, c, query
}

func TestRemovalServiceInspectionRequiresPairedOwnerAndStableJournal(t *testing.T) {
	for _, kind := range []string{"present", "absent", "no-planner", "no-inspector", "no-executor", "busy", "unconfirmed", "changed-journal", "query-failed", "cancelled", "invalid-absence", "invalid-present", "wrong-identity", "expired"} {
		t.Run(kind, func(t *testing.T) {
			s, c, query := ownedRemovalService(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			s.removal.inspect = func(context.Context) (packageapi.Removal, bool, error) {
				calls++
				switch kind {
				case "absent":
					return packageapi.Removal{}, true, nil
				case "invalid-absence":
					return c.Removal, true, nil
				case "invalid-present":
					return packageapi.Removal{}, false, nil
				case "query-failed":
					return packageapi.Removal{}, false, ErrActionUnconfirmed
				case "cancelled":
					cancel()
				case "changed-journal":
					other := connectionAfterInstallation(c)
					other.Removal = packageapi.Removal{}
					if ok, _, err := s.journal.Begin(other, time.Now()); err != nil || !ok {
						t.Fatal("owned journal transition failed", err)
					}
					if _, err := s.journal.Finish(other, "completed", time.Now()); err != nil {
						t.Fatal(err)
					}
				}
				return c.Removal, false, nil
			}
			switch kind {
			case "no-planner":
				s.removal.prepare = nil
			case "no-inspector":
				s.removal.inspect = nil
			case "no-executor":
				s.executor.remove = nil
			case "busy":
				s.executor.mu.Lock()
				defer s.executor.mu.Unlock()
			case "unconfirmed":
				raw, _ := netbirdcommand.Encode(c)
				s.removal.prepare = func(context.Context, string, packageapi.Removal) (nativeRemoval, error) {
					return &ownedNativeInstallation{run: func(context.Context) error { return ErrActionUnconfirmed }}, nil
				}
				if r, err := s.executor.Execute(ctx, raw); err != nil || r.Status != "unconfirmed" {
					t.Fatal("owned uncertain action failed", err)
				}
			case "wrong-identity":
				query.CertificateHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			case "expired":
				query.IssuedAt = query.IssuedAt.Add(-time.Hour)
				query.ExpiresAt = query.ExpiresAt.Add(-time.Hour)
			}
			before := s.journal.State(time.Now())
			r := s.removalState(ctx, query)
			want := "unavailable"
			switch kind {
			case "present", "unconfirmed":
				want = "ok"
			case "absent":
				want = "absent"
			case "busy", "changed-journal":
				want = "blocked"
			}
			if r.Outcome != want || !r.Matches(query) {
				t.Fatal("invalid removal inspection response", kind, r.Outcome)
			}
			if want == "ok" && r.Removal != c.Removal || want == "absent" && r.Removal != (packageapi.Removal{}) {
				t.Fatal("native descriptor/absence lost")
			}
			if (want == "ok" || want == "absent") && (r.State != before || calls != 1) {
				t.Fatal("inspection changed journal or omitted evidence")
			}
			if want != "ok" && want != "absent" && (r.State != (netbirdcommand.State{}) || r.Removal != (packageapi.Removal{})) {
				t.Fatal("failed inspection exposed stale evidence")
			}
		})
	}
}

func TestRemovalServiceBrokerExecutesOnceAfterAdmissionAndReplays(t *testing.T) {
	s, c, query := ownedRemovalService(t)
	var plans, runs atomic.Int32
	native := &ownedNativeInstallation{run: func(ctx context.Context) error {
		runs.Add(1)
		if receipt, err := s.journal.Lookup(c); err != nil || receipt == nil || receipt.Status != "unconfirmed" {
			t.Error("removal preceded durable intent")
		}
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(c.ExpiresAt) {
			t.Error("removal lost expiry")
		}
		return nil
	}}
	s.removal.prepare = func(ctx context.Context, id string, descriptor packageapi.Removal) (nativeRemoval, error) {
		plans.Add(1)
		if id != c.RequestID || descriptor != c.Removal {
			t.Error("review identity changed")
		}
		if receipt, err := s.journal.Lookup(c); err != nil || receipt != nil {
			t.Error("planner acquired an attempt")
		}
		return native, nil
	}
	nc := serviceBroker(t)
	if s.Bind(nc) != nil {
		t.Fatal("owned service binding failed")
	}
	if r := sendServiceControl(t, nc, query); r.Outcome != "ok" || r.Removal != c.Removal {
		t.Fatal("native ownership not exposed")
	}
	subject, _ := netbirdcommand.Subject(c.DeviceID)
	data, _ := netbirdcommand.Encode(c)
	var first netbirdcommand.Receipt
	for i := 0; i < 2; i++ {
		response, err := nc.Request(subject, data, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := netbirdcommand.DecodeReceipt(response.Data)
		if err != nil || !receipt.Matches(c) || receipt.Status != "completed" {
			t.Fatal("native result not retained", err)
		}
		if i == 0 {
			first = receipt
			s.removal = nil
			s.executor.remove = nil
		} else if receipt != first {
			t.Fatal("original receipt changed")
		}
	}
	if plans.Load() != 1 || runs.Load() != 1 || native.closed.Load() != 1 {
		t.Fatal("removal replay touched native state")
	}
}

func TestRemovalServiceRejectsChangedJournalAndJoinsRejectedPlan(t *testing.T) {
	for _, kind := range []string{"journal", "cancelled", "failed-plan", "expired-identity"} {
		t.Run(kind, func(t *testing.T) {
			s, c, _ := ownedRemovalService(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			native := &ownedNativeInstallation{run: func(context.Context) error { t.Error("rejected native plan executed"); return nil }}
			s.removal.prepare = func(context.Context, string, packageapi.Removal) (nativeRemoval, error) {
				switch kind {
				case "journal":
					other := connectionAfterInstallation(c)
					other.Removal = packageapi.Removal{}
					if ok, _, err := s.journal.Begin(other, time.Now()); err != nil || !ok {
						t.Fatal(err)
					}
					if _, err := s.journal.Finish(other, "completed", time.Now()); err != nil {
						t.Fatal(err)
					}
				case "cancelled":
					cancel()
				case "failed-plan":
					return native, ErrActionUnconfirmed
				case "expired-identity":
					s.cancel()
				}
				return native, nil
			}
			s.executor.mu.Lock()
			lease, err := s.acquireRemoval(ctx, c)
			s.executor.mu.Unlock()
			if err == nil || lease != nil || native.closed.Load() != 1 {
				t.Fatal("rejected native plan not joined")
			}
			if receipt, err := s.journal.Lookup(c); err != nil || receipt != nil {
				t.Fatal("rejected plan acquired attempt")
			}
		})
	}
}
