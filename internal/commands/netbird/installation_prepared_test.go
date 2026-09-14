package netbird

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

type ownedNativeInstallation struct {
	run    func(context.Context) error
	closed atomic.Int32
}

func (i *ownedNativeInstallation) Run(ctx context.Context) error { return i.run(ctx) }
func (i *ownedNativeInstallation) Close() error                  { i.closed.Add(1); return nil }

func TestPreparedInstallationHoldsArtifactPastPreparationExpiryAndReplaysReceipt(t *testing.T) {
	s, preparation, command := ownedPreparationService(t)
	preparation.ExpiresAt = time.Now().UTC().Add(time.Second)
	artifact := &ownedPreparedPackage{}
	s.preparation.stage = func(context.Context, packageapi.Package) (preparedPackage, error) { return artifact, nil }
	if r := s.prepare(t.Context(), preparation); r.Outcome != "prepared" {
		t.Fatal("fixture was not prepared")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var plans atomic.Int32
	native := &ownedNativeInstallation{run: func(ctx context.Context) error {
		if receipt, err := s.journal.Lookup(command); err != nil || receipt == nil || receipt.Status != "unconfirmed" {
			t.Error("native execution preceded durable admission")
		}
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	s.installation = func(_ context.Context, got preparedPackage, pkg packageapi.Package) (nativeInstallation, error) {
		plans.Add(1)
		if got != artifact || pkg != command.Package {
			t.Error("native plan lost exact prepared source")
		}
		return native, nil
	}
	s.executor.install = s.acquireInstallation
	nc := serviceBroker(t)
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	capability := serviceControl(command, "state")
	capability.Kind = "installation-state"
	if r := sendServiceControl(t, nc, capability); r.Outcome != "ok" || r.State.Status != "ready" {
		t.Fatal("configured native capability missing")
	}
	data, _ := netbirdcommand.Encode(command)
	finished := make(chan netbirdcommand.Receipt, 1)
	go func() { r, _ := s.executor.Execute(t.Context(), data); finished <- r }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native execution did not start")
	}
	// The cleanup worker must skip the artifact while the command retains it,
	// even when the original preparation lease expires during native execution.
	timer := time.NewTimer(1100 * time.Millisecond)
	<-timer.C
	if artifact.closed.Load() != 0 || native.closed.Load() != 0 {
		t.Fatal("expiry removed an in-use package")
	}
	if r := sendServiceControl(t, nc, serviceControl(command, "state")); r.State.Status != "busy" {
		t.Fatal("native execution lost common barrier")
	}
	next := connectionAfterInstallation(command)
	raw, _ := netbirdcommand.Encode(next)
	if r, err := s.executor.Execute(t.Context(), raw); err != nil || r.Status != "busy" {
		t.Fatal("connection overlapped installation", err)
	}
	close(release)
	result := <-finished
	if !result.Matches(command) || result.Status != "completed" || artifact.closed.Load() != 1 || native.closed.Load() != 1 {
		t.Fatal("native result or joined cleanup missing")
	}
	if again, err := s.executor.Execute(t.Context(), data); err != nil || again != result || plans.Load() != 1 {
		t.Fatal("lost prepared cache repeated installation", err)
	}
}

func TestPreparedInstallationRejectsChangedAuthorityAndRetainsNoAttempt(t *testing.T) {
	for _, kind := range []string{"missing", "request", "review", "source", "certificate", "expired", "journal"} {
		t.Run(kind, func(t *testing.T) {
			s, p, c := ownedPreparationService(t)
			artifact := &ownedPreparedPackage{}
			s.preparation.stage = func(context.Context, packageapi.Package) (preparedPackage, error) { return artifact, nil }
			if kind != "missing" {
				if r := s.prepare(t.Context(), p); r.Outcome != "prepared" {
					t.Fatal("fixture")
				}
			}
			calls := 0
			s.installation = func(context.Context, preparedPackage, packageapi.Package) (nativeInstallation, error) {
				calls++
				return nil, errors.New("must not enter")
			}
			s.executor.install = s.acquireInstallation
			switch kind {
			case "request":
				c.RequestID = uuid.NewString()
			case "review":
				c.Revision = strings.Repeat("f", 64)
			case "source":
				c.Package.URL += "-changed"
			case "certificate":
				c.CertificateHash = strings.Repeat("f", 64)
			case "expired":
				s.preparation.mu.Lock()
				s.preparation.request.ExpiresAt = time.Now().Add(-time.Second)
				s.preparation.mu.Unlock()
			case "journal":
				other := connectionAfterInstallation(c)
				s.executor.run = func(context.Context, netbirdcommand.Command) error { return nil }
				data, _ := netbirdcommand.Encode(other)
				if r, err := s.executor.Execute(t.Context(), data); err != nil || r.Status != "completed" {
					t.Fatal("journal fixture failed")
				}
			}
			before := s.journal.State(time.Now())
			data, _ := netbirdcommand.Encode(c)
			r, err := s.executor.Execute(t.Context(), data)
			if err == nil && r.Status != "rejected" || calls != 0 || s.journal.State(time.Now()) != before {
				t.Fatal("unprepared native command admitted", err)
			}
		})
	}
}

func TestInstallationPreparationRaceCannotSkipAtomicJournalRevision(t *testing.T) {
	e, journal, c, _ := ownedInstallation(t)
	before := journal.State(time.Now())
	runs, releases := 0, 0
	e.install = func(ctx context.Context, _ netbirdcommand.Command) (*installationLease, error) {
		other := connectionAfterInstallation(c)
		hash, _ := other.Digest()
		now := time.Now().UTC()
		withdraw := netbirdcommand.ControlRequest{Version: netbirdcommand.RecoveryVersion, Identity: c.Identity, RequestID: uuid.NewString(), Kind: "withdraw", ReferenceID: other.RequestID, CommandHash: hash, Revision: other.Revision, Operation: other.Operation, IssuedAt: now, ExpiresAt: now.Add(time.Second)}
		data, _ := netbirdcommand.EncodeControl(withdraw)
		if r, err := journal.Control(ctx, data); err != nil || r.Outcome != "ok" {
			t.Fatal("concurrent withdrawal fixture failed")
		}
		return &installationLease{revision: before.Revision, run: func(context.Context) error { runs++; return nil }, release: func() error { releases++; return nil }}, nil
	}
	data, _ := netbirdcommand.Encode(c)
	if _, err := e.Execute(t.Context(), data); err == nil || runs != 0 || releases != 1 {
		t.Fatal("journal changed between preparation and admission")
	}
	if r, err := journal.Lookup(c); err != nil || r != nil {
		t.Fatal("rejected installation acquired a permanent attempt")
	}
}

func TestInstallationCleanupFailureRetainsUncertainty(t *testing.T) {
	e, journal, c, _ := ownedInstallation(t)
	e.install = func(context.Context, netbirdcommand.Command) (*installationLease, error) {
		return &installationLease{revision: journal.State(time.Now()).Revision, run: func(context.Context) error { return nil }, release: func() error { return errors.New("owned cleanup failure") }}, nil
	}
	data, _ := netbirdcommand.Encode(c)
	r, err := e.Execute(t.Context(), data)
	if err != nil || r.Status != "unconfirmed" || journal.State(time.Now()).Status != "unconfirmed" {
		t.Fatal("cleanup failure invented completion", err)
	}
}

func TestPreparedInstallationServiceCloseJoinsNativeExecution(t *testing.T) {
	s, p, c := ownedPreparationService(t)
	artifact := &ownedPreparedPackage{}
	s.preparation.stage = func(context.Context, packageapi.Package) (preparedPackage, error) { return artifact, nil }
	if r := s.prepare(t.Context(), p); r.Outcome != "prepared" {
		t.Fatal("fixture not prepared")
	}
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	native := &ownedNativeInstallation{run: func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return ctx.Err()
	}}
	s.installation = func(context.Context, preparedPackage, packageapi.Package) (nativeInstallation, error) {
		return native, nil
	}
	s.executor.install = s.acquireInstallation
	nc := serviceBroker(t)
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	subject, _ := netbirdcommand.Subject(c.DeviceID)
	data, _ := netbirdcommand.Encode(c)
	if err := nc.PublishRequest(subject, nats.NewInbox(), data); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native command did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("service did not cancel native execution")
	}
	select {
	case <-closed:
		t.Fatal("service closed while native execution remained live")
	default:
	}
	if s.journal.State(time.Now()).Status == "unavailable" || artifact.closed.Load() != 0 {
		t.Fatal("shutdown released journal or artifact early")
	}
	close(release)
	if err := <-closed; err != nil || artifact.closed.Load() != 1 || native.closed.Load() != 1 {
		t.Fatal("shutdown did not join and clean native ownership", err)
	}
}
