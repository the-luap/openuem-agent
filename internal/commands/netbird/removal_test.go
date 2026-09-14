package netbird

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
)

func ownedRemoval(t *testing.T) (*DurableExecutor, *netbirdjournal.Journal, netbirdcommand.Command, string) {
	e, j, c, path := ownedInstallation(t)
	c.Version, c.Operation, c.Package = netbirdcommand.RemovalVersion, "uninstall", packageapi.Package{}
	c.Removal = packageapi.Removal{Schema: 1, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", StateDigest: strings.Repeat("f", 64)}
	c.ExpiresAt = c.IssuedAt.Add(netbirdcommand.RemovalLifetime)
	return e, j, c, path
}

func TestRemovalRequiresSeparateNativeOwnerBeforeJournalAdmission(t *testing.T) {
	e, j, c, _ := ownedRemoval(t)
	called := 0
	e.run = func(context.Context, netbirdcommand.Command) error { called++; return nil }
	e.install = installationFixture(j, func(context.Context, netbirdcommand.Command) error { called++; return nil })
	data, err := netbirdcommand.Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	before := j.State(time.Now())
	for range 2 {
		r, err := e.Execute(t.Context(), data)
		if err != nil || !r.Matches(c) || r.Status != "rejected" {
			t.Fatal("unconfigured removal was not rejected", err)
		}
	}
	if receipt, err := j.Lookup(c); err != nil || receipt != nil || called != 0 || j.State(time.Now()) != before {
		t.Fatal("removal fell through to another runner or acquired an attempt", err)
	}
}

func TestRemovalDurableAttemptRetainsExactStateAndResultAcrossRestart(t *testing.T) {
	e, j, c, path := ownedRemoval(t)
	calls := 0
	e.remove = installationFixture(j, func(ctx context.Context, got netbirdcommand.Command) error {
		calls++
		if got != c {
			t.Error("removal inspection changed")
		}
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(c.ExpiresAt) {
			t.Error("native removal lost deadline")
		}
		if receipt, err := j.Lookup(c); err != nil || receipt == nil || receipt.Status != "unconfirmed" {
			t.Error("native removal preceded durable intent", err)
		}
		return nil
	})
	data, _ := netbirdcommand.Encode(c)
	r, err := e.Execute(t.Context(), data)
	if err != nil || r.Status != "completed" || !r.Matches(c) || calls != 1 {
		t.Fatal("removal was not confirmed once", err)
	}
	changed := c
	changed.Removal.StateDigest = strings.Repeat("e", 64)
	other, _ := netbirdcommand.Encode(changed)
	if _, err := e.Execute(t.Context(), other); err == nil || calls != 1 {
		t.Fatal("same UUID accepted changed installed state")
	}
	j.Close()
	current := c.Identity
	current.CertificateHash = strings.Repeat("e", 64)
	j, err = netbirdjournal.Open(path, strings.Repeat("b", 64), current, netbirdjournal.Boot{Platform: "linux", ID: "90000000-0000-4000-8000-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	at := time.Now().UTC()
	hash, _ := c.Digest()
	query := netbirdcommand.ControlRequest{Version: netbirdcommand.RecoveryVersion, Identity: current, RequestID: uuid.NewString(), Kind: "receipt", ReferenceID: c.RequestID, CommandHash: hash, Revision: c.Revision, Operation: "uninstall", IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.ControlLifetime)}
	body, _ := netbirdcommand.EncodeControl(query)
	proof, err := j.Control(t.Context(), body)
	if err != nil || !proof.Matches(query) || proof.Receipt != r {
		t.Fatal("renewal lost original removal evidence", err)
	}
}

func TestRemovalRetainsUncertaintyAndJoinsNativeOwner(t *testing.T) {
	e, j, c, _ := ownedRemoval(t)
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var starts, closes atomic.Int32
	e.remove = func(context.Context, netbirdcommand.Command) (*nativePackageLease, error) {
		return &nativePackageLease{revision: j.State(time.Now()).Revision, run: func(ctx context.Context) error {
			starts.Add(1)
			close(entered)
			<-ctx.Done()
			<-release
			return ctx.Err()
		}, release: func() error { closes.Add(1); return nil }}, nil
	}
	data, _ := netbirdcommand.Encode(c)
	var result netbirdcommand.Receipt
	var executionError error
	go func() { result, executionError = e.Execute(parent, data); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native owner did not start")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("cancellation did not join native removal")
	case <-time.After(20 * time.Millisecond):
	}
	if j.State(time.Now()).Status != "busy" || closes.Load() != 0 {
		t.Fatal("pending removal released ownership before join")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("native removal did not join")
	}
	if executionError != nil || result.Status != "unconfirmed" || closes.Load() != 1 {
		t.Fatal("cancelled removal lost uncertainty", executionError)
	}
	again, err := e.Execute(t.Context(), data)
	if err != nil || again != result || starts.Load() != 1 || closes.Load() != 1 {
		t.Fatal("uncertain removal was repeated", err)
	}
	next := connectionAfterInstallation(c)
	next.Removal = packageapi.Removal{}
	nextData, _ := netbirdcommand.Encode(next)
	e.run = func(context.Context, netbirdcommand.Command) error {
		t.Error("connection crossed unresolved removal")
		return nil
	}
	if _, err := e.Execute(t.Context(), nextData); err == nil {
		t.Fatal("unresolved removal lost common barrier")
	}
}

func TestRemovalChangedJournalOrFailedCleanupCannotConfirm(t *testing.T) {
	for _, mode := range []string{"journal", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			e, j, c, _ := ownedRemoval(t)
			runs, closes := 0, 0
			e.remove = func(context.Context, netbirdcommand.Command) (*nativePackageLease, error) {
				revision := j.State(time.Now()).Revision
				if mode == "journal" {
					other := connectionAfterInstallation(c)
					other.Removal = packageapi.Removal{}
					if ok, _, err := j.Begin(other, time.Now()); err != nil || !ok {
						t.Fatal(err)
					}
					if _, err := j.Finish(other, "completed", time.Now()); err != nil {
						t.Fatal(err)
					}
				}
				return &nativePackageLease{revision: revision, run: func(context.Context) error { runs++; return nil }, release: func() error {
					closes++
					if mode == "cleanup" {
						return errors.New("owned cleanup failure")
					}
					return nil
				}}, nil
			}
			data, _ := netbirdcommand.Encode(c)
			r, err := e.Execute(t.Context(), data)
			if mode == "journal" {
				if err == nil || runs != 0 || closes != 1 {
					t.Fatal("stale inspection admitted native removal", err)
				}
			} else if err != nil || r.Status != "unconfirmed" || runs != 1 || closes != 1 {
				t.Fatal("failed cleanup confirmed removal", err)
			}
		})
	}
}

func TestRemovalServiceRejectsUnconfiguredNativeWorkAndInspection(t *testing.T) {
	e, j, c, _ := ownedRemoval(t)
	nc := serviceBroker(t)
	s, err := NewDurableService(t.Context(), j, c.Identity, c.ExpiresAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.executor = e
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	query := netbirdcommand.ControlRequest{Version: netbirdcommand.RemovalInspectionVersion, Identity: c.Identity, RequestID: uuid.NewString(), Kind: "removal-state", IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.RemovalInspectionLifetime)}
	if r := sendServiceControl(t, nc, query); r.Outcome != "unavailable" || r.Removal != (packageapi.Removal{}) {
		t.Fatal("unconfigured native service advertised ownership")
	}
	subject, _ := netbirdcommand.Subject(c.DeviceID)
	data, _ := netbirdcommand.Encode(c)
	before := j.State(time.Now())
	for range 2 {
		response, err := nc.Request(subject, data, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		r, err := netbirdcommand.DecodeReceipt(response.Data)
		if err != nil || !r.Matches(c) || r.Status != "rejected" {
			t.Fatal("service did not reject unconfigured removal", err)
		}
	}
	if before != j.State(time.Now()) {
		t.Fatal("rejected broker removal changed the journal")
	}
}
