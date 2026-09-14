package netbird

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/netbirdinstall"
)

type ownedPreparedPackage struct {
	closed   atomic.Int32
	changed  atomic.Bool
	closeErr error
}

func (p *ownedPreparedPackage) Verify(ctx context.Context, _ packageapi.Package) error {
	if p.closed.Load() != 0 || p.changed.Load() {
		return errors.New("owned changed package")
	}
	return ctx.Err()
}
func (p *ownedPreparedPackage) Close() error { p.closed.Add(1); return p.closeErr }

func ownedPreparationService(t *testing.T) (*DurableService, netbirdcommand.PreparationRequest, netbirdcommand.Command) {
	t.Helper()
	_, journal, command, _ := ownedInstallation(t)
	s, err := NewDurableService(t.Context(), journal, command.Identity, command.ExpiresAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	s.preparation = &preparationOwner{}
	s.startPreparationCleanup()
	t.Cleanup(func() { s.Close() })
	p := netbirdcommand.PreparationRequest{Version: netbirdcommand.PreparationVersion, Identity: command.Identity, RequestID: command.RequestID, Revision: command.Revision, JournalRevision: journal.State(time.Now()).Revision, Package: command.Package, IssuedAt: command.IssuedAt, ExpiresAt: command.ExpiresAt}
	return s, p, command
}

func sendPreparation(t *testing.T, nc *nats.Conn, p netbirdcommand.PreparationRequest) netbirdcommand.PreparationResponse {
	t.Helper()
	data, err := netbirdcommand.EncodePreparation(p)
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := netbirdcommand.PreparationSubject(p.DeviceID)
	msg, err := nc.Request(subject, data, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := netbirdcommand.DecodePreparationResponse(msg.Data, p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(msg.Data), "source-secret") {
		t.Fatal("private source in response")
	}
	return r
}

func TestPreparationBrokerReplaySourceBindingAndReadiness(t *testing.T) {
	s, p, command := ownedPreparationService(t)
	var calls atomic.Int32
	artifact := &ownedPreparedPackage{}
	s.preparation.stage = func(ctx context.Context, pkg packageapi.Package) (preparedPackage, error) {
		calls.Add(1)
		if pkg != p.Package {
			t.Error("source changed")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Minute {
			t.Error("unbounded preparation")
		}
		return artifact, nil
	}
	nc := serviceBroker(t)
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	capability := serviceControl(command, "state")
	capability.Kind = "preparation-state"
	if r := sendServiceControl(t, nc, capability); r.Outcome != "ok" || r.State.Revision != p.JournalRevision {
		t.Fatal("preparation capability missing")
	}
	before := s.journal.State(time.Now())
	for range 2 {
		if r := sendPreparation(t, nc, p); r.Outcome != "prepared" {
			t.Fatal("exact replay lost preparation")
		}
	}
	if calls.Load() != 1 || s.journal.State(time.Now()) != before {
		t.Fatal("preparation repeated download or admitted command")
	}
	for _, mutate := range []func(*netbirdcommand.PreparationRequest){
		func(p *netbirdcommand.PreparationRequest) { p.Package.URL += "-changed" },
		func(p *netbirdcommand.PreparationRequest) { p.Revision = strings.Repeat("f", 64) },
		func(p *netbirdcommand.PreparationRequest) { p.ExpiresAt = p.ExpiresAt.Add(-time.Second) },
	} {
		changed := p
		mutate(&changed)
		if r := sendPreparation(t, nc, changed); r.Outcome != "conflict" {
			t.Fatal("changed authority inherited preparation")
		}
	}
	other := p
	other.RequestID = uuid.NewString()
	if r := sendPreparation(t, nc, other); r.Outcome != "blocked" {
		t.Fatal("second package replaced live preparation")
	}
	data, _ := netbirdcommand.Encode(command)
	subject, _ := netbirdcommand.Subject(command.DeviceID)
	msg, err := nc.Request(subject, data, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := netbirdcommand.DecodeReceipt(msg.Data)
	if err != nil || receipt.Status != "rejected" || s.journal.State(time.Now()) != before {
		t.Fatal("preparation enabled installation", err)
	}
	replacement, err := nats.Connect(nc.ConnectedUrl(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err = s.Bind(replacement); err != nil {
		t.Fatal(err)
	}
	if err = nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if r := sendPreparation(t, nc, p); r.Outcome != "prepared" || calls.Load() != 1 {
		t.Fatal("connection replacement lost exact preparation")
	}
	artifact.changed.Store(true)
	if r := sendPreparation(t, nc, p); r.Outcome != "unavailable" || artifact.closed.Load() != 1 {
		t.Fatal("changed private file retained readiness")
	}
}

func TestPreparationRejectsForeignExpiredAndUnconfiguredRequests(t *testing.T) {
	s, p, command := ownedPreparationService(t)
	var calls atomic.Int32
	s.preparation.stage = func(context.Context, packageapi.Package) (preparedPackage, error) {
		calls.Add(1)
		return &ownedPreparedPackage{}, nil
	}
	nc := serviceBroker(t)
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	subject, _ := netbirdcommand.PreparationSubject(p.DeviceID)
	for _, mutate := range []func(*netbirdcommand.PreparationRequest){
		func(p *netbirdcommand.PreparationRequest) { p.SiteID++ },
		func(p *netbirdcommand.PreparationRequest) { p.CertificateHash = strings.Repeat("f", 64) },
		func(p *netbirdcommand.PreparationRequest) {
			p.IssuedAt = time.Now().Add(-time.Minute)
			p.ExpiresAt = time.Now().Add(-time.Second)
		},
		func(p *netbirdcommand.PreparationRequest) {
			p.IssuedAt = s.expires.Add(-time.Minute)
			p.ExpiresAt = s.expires.Add(time.Second)
		},
	} {
		changed := p
		mutate(&changed)
		data, err := netbirdcommand.EncodePreparation(changed)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := nc.Request(subject, data, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = netbirdcommand.DecodePreparationResponse(msg.Data, changed); err == nil {
			t.Fatal("foreign or expired request accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected request downloaded package")
	}
	// The ordinary constructor has no staging capability, even for an individual
	// identity whose journal can execute connection and registration commands.
	_, journal, otherCommand, _ := ownedInstallation(t)
	other, err := NewDurableService(t.Context(), journal, otherCommand.Identity, otherCommand.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = other.Bind(nc); err != nil {
		t.Fatal(err)
	}
	capability := serviceControl(otherCommand, "state")
	capability.Kind = "preparation-state"
	if r := sendServiceControl(t, nc, capability); r.Outcome != "unavailable" {
		t.Fatal("ordinary journal advertised preparation")
	}
	query := serviceControl(command, "state")
	query.Kind = "preparation-state"
	data, _ := netbirdcommand.EncodeControl(query)
	if r, err := s.journal.Control(t.Context(), data); err == nil && r.Outcome == "ok" {
		t.Fatal("bare journal advertised preparation")
	}
}

func TestPreparationSerializesCommandsAndRejectsChangedJournalDuringDownload(t *testing.T) {
	s, p, command := ownedPreparationService(t)
	entered, release := make(chan struct{}), make(chan struct{})
	artifact := &ownedPreparedPackage{}
	s.preparation.stage = func(ctx context.Context, _ packageapi.Package) (preparedPackage, error) {
		close(entered)
		select {
		case <-release:
			return artifact, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	nc := serviceBroker(t)
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	result := make(chan *nats.Msg, 1)
	data, _ := netbirdcommand.EncodePreparation(p)
	subject, _ := netbirdcommand.PreparationSubject(p.DeviceID)
	go func() { msg, _ := nc.Request(subject, data, 3*time.Second); result <- msg }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("download not entered")
	}
	connection := connectionAfterInstallation(command)
	s.executor.run = func(context.Context, netbirdcommand.Command) error {
		t.Error("command overlapped preparation")
		return nil
	}
	raw, _ := netbirdcommand.Encode(connection)
	if r, err := s.executor.Execute(t.Context(), raw); err != nil || r.Status != "busy" {
		t.Fatal("preparation did not hold executor", err)
	}
	hash, _ := connection.Digest()
	now := time.Now().UTC()
	withdraw := netbirdcommand.ControlRequest{Version: netbirdcommand.RecoveryVersion, Identity: p.Identity, RequestID: uuid.NewString(), Kind: "withdraw", ReferenceID: connection.RequestID, CommandHash: hash, Revision: connection.Revision, Operation: connection.Operation, IssuedAt: now, ExpiresAt: now.Add(time.Second)}
	if r := sendServiceControl(t, nc, withdraw); r.Outcome != "ok" {
		t.Fatal("readiness change fixture failed")
	}
	close(release)
	msg := <-result
	if msg == nil {
		t.Fatal("preparation response lost")
	}
	r, err := netbirdcommand.DecodePreparationResponse(msg.Data, p)
	if err != nil || r.Outcome != "blocked" || artifact.closed.Load() != 1 {
		t.Fatal("changed journal inherited downloaded package", err)
	}
}

func TestPreparationCloseJoinsStageAndCleansBeforeServiceReturns(t *testing.T) {
	s, p, _ := ownedPreparationService(t)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	artifact := &ownedPreparedPackage{}
	s.preparation.stage = func(ctx context.Context, _ packageapi.Package) (preparedPackage, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return artifact, nil
	}
	nc := serviceBroker(t)
	if err := s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	data, _ := netbirdcommand.EncodePreparation(p)
	subject, _ := netbirdcommand.PreparationSubject(p.DeviceID)
	if err := nc.PublishRequest(subject, nats.NewInbox(), data); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("stage not entered")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("close did not cancel stage")
	}
	select {
	case <-closed:
		t.Fatal("service closed while stage remained live")
	default:
	}
	if s.journal.State(time.Now()).Status == "unavailable" {
		t.Fatal("journal closed before stage joined")
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if artifact.closed.Load() != 1 {
		t.Fatal("shutdown did not clean late artifact exactly once")
	}
}

func TestPreparationExpiryAndCleanupFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "expiry", true: "cleanup-failure"}[fail], func(t *testing.T) {
			s, p, _ := ownedPreparationService(t)
			p.ExpiresAt = time.Now().UTC().Add(100 * time.Millisecond)
			artifact := &ownedPreparedPackage{}
			if fail {
				artifact.closeErr = errors.New("owned cleanup failure")
			}
			s.preparation.stage = func(context.Context, packageapi.Package) (preparedPackage, error) { return artifact, nil }
			if r := s.prepare(t.Context(), p); r.Outcome != "prepared" {
				t.Fatal("preparation failed")
			}
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for artifact.closed.Load() == 0 {
				select {
				case <-deadline.C:
					t.Fatal("expired artifact retained")
				case <-tick.C:
				}
			}
			if err := s.Close(); (err != nil) != fail {
				t.Fatal("cleanup failure was discarded", err)
			}
		})
	}
}

func TestPreparationCannotBypassRetainedExecutionOrChangedJournal(t *testing.T) {
	for _, status := range []string{"completed", "unconfirmed"} {
		t.Run(status, func(t *testing.T) {
			s, p, command := ownedPreparationService(t)
			artifact := &ownedPreparedPackage{}
			calls := 0
			s.preparation.stage = func(context.Context, packageapi.Package) (preparedPackage, error) { calls++; return artifact, nil }
			if r := s.prepare(t.Context(), p); r.Outcome != "prepared" {
				t.Fatal("preparation not retained")
			}
			connection := connectionAfterInstallation(command)
			s.executor.run = func(context.Context, netbirdcommand.Command) error {
				if status == "unconfirmed" {
					return errors.New("owned uncertain execution")
				}
				return nil
			}
			raw, _ := netbirdcommand.Encode(connection)
			if r, err := s.executor.Execute(t.Context(), raw); err != nil || r.Status != status {
				t.Fatal("owned journal transition failed", err)
			}
			if r := s.prepare(t.Context(), p); r.Outcome != "blocked" || calls != 1 || artifact.closed.Load() != 1 {
				t.Fatal("old journal revision inherited preparation")
			}
			if status == "unconfirmed" {
				p.JournalRevision = s.journal.State(time.Now()).Revision
				if r := s.prepare(t.Context(), p); r.Outcome != "blocked" || calls != 1 {
					t.Fatal("unconfirmed barrier bypassed")
				}
			}
		})
	}
}

func TestPreparationConcurrentAdmissionIsBoundedAndFailurePreservesJournal(t *testing.T) {
	s, p, _ := ownedPreparationService(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s.preparation.stage = func(ctx context.Context, _ packageapi.Package) (preparedPackage, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("owned failed preparation")
	}
	before := s.journal.State(time.Now())
	finished := make(chan netbirdcommand.PreparationResponse, 1)
	go func() { finished <- s.prepare(t.Context(), p) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("preparation not entered")
	}
	results := make(chan netbirdcommand.PreparationResponse, 8)
	for range 8 {
		go func() { results <- s.prepare(t.Context(), p) }()
	}
	for range 8 {
		if r := <-results; r.Outcome != "blocked" {
			t.Fatal("concurrent preparation was not excluded")
		}
	}
	close(release)
	if r := <-finished; r.Outcome != "unavailable" || calls.Load() != 1 || s.journal.State(time.Now()) != before {
		t.Fatal("failed preparation altered durable evidence")
	}
}

func TestNativePreparationConstructorRejectsSharedAndUnsafeRoots(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix preparation")
	}
	_, journal, c, _ := ownedInstallation(t)
	root := filepath.Join(t.TempDir(), "preparation")
	if err := os.Chmod(filepath.Dir(root), 0700); err != nil {
		t.Fatal(err)
	}
	shared := c.Identity
	shared.Individual, shared.CertificateHash = false, ""
	if s, err := NewDurableServiceWithPreparation(t.Context(), journal, shared, c.ExpiresAt, root); err == nil {
		s.Close()
		t.Fatal("shared preparation enabled")
	}
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if s, err := NewDurableServiceWithPreparation(t.Context(), journal, c.Identity, c.ExpiresAt, root); err == nil {
		s.Close()
		t.Fatal("unsafe preparation root accepted")
	}
	if journal.State(time.Now()).Status != "ready" {
		t.Fatal("failed constructor took journal ownership")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := NewDurableServiceWithPreparation(t.Context(), journal, c.Identity, c.ExpiresAt, root)
	if err != nil {
		t.Fatal(err)
	}
	supported := netbirdinstall.RemovalRecoverySupported()
	if (s.removalRecovery != nil) != supported || (s.executor.recoverRemoval != nil) != supported {
		t.Fatal("native recovery inspection and execution were not configured together")
	}
	if supported && (s.removalRecovery.inspect == nil || s.removalRecovery.prepare == nil) {
		t.Fatal("native recovery owner is incomplete")
	}
	absenceSupported := netbirdinstall.RemovalSupported()
	if (s.removalAbsence != nil) != absenceSupported || (s.executor.verifyRemovalAbsence != nil) != absenceSupported {
		t.Fatal("current absence inspection and verification were not configured together")
	}
	if absenceSupported && (s.removalAbsence.inspect == nil || s.removalAbsence.prepare == nil) {
		t.Fatal("current absence owner is incomplete")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNativePreparationFailurePreservesUnexpectedLiveStage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix preparation")
	}
	_, journal, c, _ := ownedInstallation(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "preparation")
	s, err := NewDurableServiceWithPreparation(t.Context(), journal, c.Identity, c.ExpiresAt, root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	path := filepath.Join(root, "netbird-package-"+uuid.NewString())
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(path, "package.deb")
	if err = os.WriteFile(path, []byte("preserve unexpected live file"), 0600); err != nil {
		t.Fatal(err)
	}
	// An incompatible target additionally prevents any external download in this
	// fixture. A live root check must not turn into broad startup recovery.
	if runtime.GOOS == "linux" {
		c.Package.Platform, c.Package.Format, c.Package.PackageID, c.Package.URL = "macos", "pkg", "io.netbird.client", "https://never-request.example.test/netbird.pkg"
	}
	p := netbirdcommand.PreparationRequest{Version: netbirdcommand.PreparationVersion, Identity: c.Identity, RequestID: c.RequestID, Revision: c.Revision, JournalRevision: journal.State(time.Now()).Revision, Package: c.Package, IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt}
	if r := s.prepare(t.Context(), p); r.Outcome != "unavailable" {
		t.Fatal("failed native stage advertised preparation")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "preserve unexpected live file" {
		t.Fatal("failure deleted a preserved replacement")
	}
	control := serviceControl(c, "state")
	control.Kind = "preparation-state"
	if r := s.preparationState(control); r.Outcome != "unavailable" {
		t.Fatal("unexpected files did not stop preparation")
	}
	if err = s.Close(); err == nil {
		t.Fatal("cleanup conflict disappeared during shutdown")
	}
}
