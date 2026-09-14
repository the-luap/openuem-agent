package netbird

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
)

func ownedInstallation(t *testing.T) (*DurableExecutor, *netbirdjournal.Journal, netbirdcommand.Command, string) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	c := netbirdcommand.Command{Version: netbirdcommand.InstallationVersion, Identity: netbirdcommand.Identity{DeviceID: uuid.NewString(), TenantID: 1, SiteID: 2, Individual: true, CertificateHash: strings.Repeat("c", 64)}, RequestID: uuid.NewString(), Revision: strings.Repeat("a", 64), Operation: "install", IssuedAt: at, ExpiresAt: at.Add(netbirdcommand.InstallationLifetime)}
	c.Package = packageapi.Package{Schema: 1, ApprovalID: uuid.NewString(), TenantID: 1, Platform: "linux", Architecture: "arm64", Format: "deb", PackageID: "netbird", Version: "0.78.1", URL: "https://owned-package.example.test/netbird.deb?private=source-secret", Size: 1234, SHA256: strings.Repeat("d", 64)}
	path := filepath.Join(t.TempDir(), "journal")
	j, err := netbirdjournal.Open(path, strings.Repeat("b", 64), c.Identity, netbirdjournal.Boot{Platform: "linux", ID: "90000000-0000-4000-8000-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	e, err := NewDurableExecutor(j)
	if err != nil {
		t.Fatal(err)
	}
	return e, j, c, path
}

func connectionAfterInstallation(c netbirdcommand.Command) netbirdcommand.Command {
	c.Version, c.Operation, c.ManagementURL = netbirdcommand.Version, "up", "https://owned-management.example.test"
	c.Package = packageapi.Package{}
	c.RequestID = uuid.NewString()
	c.ExpiresAt = c.IssuedAt.Add(netbirdcommand.Lifetime)
	return c
}

func TestInstallationDisabledRunnerRejectsBeforeDurableAdmission(t *testing.T) {
	e, j, c, _ := ownedInstallation(t)
	called := 0
	e.run = func(context.Context, netbirdcommand.Command) error { called++; return nil }
	data, err := netbirdcommand.Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	before := j.State(time.Now())
	for range 2 {
		r, err := e.Execute(t.Context(), data)
		if err != nil || !r.Matches(c) || r.Status != "rejected" {
			t.Fatal("unconfigured installer was not explicitly rejected", err)
		}
	}
	if got, err := j.Lookup(c); err != nil || got != nil || called != 0 || j.State(time.Now()) != before {
		t.Fatal("unconfigured installer acquired an attempt or used the connection runner", err)
	}
}

func TestInstallationDurableAttemptBindsPackageAndSurvivesRestart(t *testing.T) {
	e, j, c, path := ownedInstallation(t)
	calls := 0
	e.run = func(context.Context, netbirdcommand.Command) error {
		t.Error("installation reached the connection runner")
		return ErrInvalidAction
	}
	e.install = func(ctx context.Context, got netbirdcommand.Command) error {
		calls++
		if got != c {
			t.Error("installation intent changed")
		}
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(c.ExpiresAt) {
			t.Error("native execution did not inherit the command deadline")
		}
		if receipt, err := j.Lookup(c); err != nil || receipt == nil || receipt.Status != "unconfirmed" {
			t.Error("installation ran before its permanent attempt")
		}
		return nil
	}
	data, _ := netbirdcommand.Encode(c)
	first, err := e.Execute(t.Context(), data)
	if err != nil || !first.Matches(c) || first.Status != "completed" {
		t.Fatal("installation did not retain completion", err)
	}
	changed := c
	changed.Package.URL += "-changed"
	raw, _ := netbirdcommand.Encode(changed)
	if _, err = e.Execute(t.Context(), raw); err == nil {
		t.Fatal("changed package source reused a completed UUID")
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := netbirdjournal.Open(path, strings.Repeat("b", 64), c.Identity, netbirdjournal.Boot{Platform: "linux", ID: "90000000-0000-4000-8000-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, err := NewDurableExecutor(reopened)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return c.ExpiresAt.Add(time.Hour) }
	again, err := restarted.Execute(t.Context(), data)
	if err != nil || again != first || calls != 1 {
		t.Fatal("restart, missing runner or expiry lost retained evidence", err)
	}
	files, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		body, err := os.ReadFile(filepath.Join(path, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{c.Package.URL, "source-secret", "owned-package.example.test", "\"package\""} {
			if strings.Contains(string(body), private) {
				t.Fatal("journal retained private package source")
			}
		}
	}
}

func TestInstallationSharesConnectionAndRegistrationUncertaintyBarrier(t *testing.T) {
	e, j, c, _ := ownedInstallation(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	e.install = func(ctx context.Context, got netbirdcommand.Command) error {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return ErrActionUnconfirmed
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	e.run = func(context.Context, netbirdcommand.Command) error { calls.Add(1); return nil }
	raw, _ := netbirdcommand.Encode(c)
	done := make(chan error, 1)
	go func() { _, err := e.Execute(ctx, raw); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	next := connectionAfterInstallation(c)
	data, _ := netbirdcommand.Encode(next)
	r, err := e.Execute(ctx, data)
	if err != nil || !r.Matches(next) || r.Status != "busy" {
		t.Error("connection overlapped installation", err)
	}
	if state := j.State(time.Now()); state.Status != "busy" || state.CanRelease {
		t.Error("installation did not hold the common journal barrier")
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"up", "register", "install"} {
		follow := next
		if operation == "register" {
			follow.Version, follow.Operation, follow.SetupKey = netbirdcommand.RegistrationVersion, "register", "owned-key"
		}
		if operation == "install" {
			follow = c
			follow.RequestID = uuid.NewString()
		}
		data, _ = netbirdcommand.Encode(follow)
		if _, err = e.Execute(ctx, data); err == nil {
			t.Errorf("uncertain installation admitted %s", operation)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("unresolved installation repeated execution")
	}
}

func TestInstallationBrokerRejectsWithoutRunnerAndRecoversLostReply(t *testing.T) {
	for _, enabledFixture := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "owned-runner"}[enabledFixture], func(t *testing.T) {
			e, j, c, _ := ownedInstallation(t)
			var calls atomic.Int32
			if enabledFixture {
				e.install = func(context.Context, netbirdcommand.Command) error { calls.Add(1); return ErrActionUnconfirmed }
			}
			nc := serviceBroker(t)
			s, err := NewDurableService(t.Context(), j, c.Identity, c.ExpiresAt.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			s.executor = e
			if err = s.Bind(nc); err != nil {
				t.Fatal(err)
			}
			subject, _ := netbirdcommand.Subject(c.DeviceID)
			data, _ := netbirdcommand.Encode(c)
			// No listener retains the first response. The ordered second callback
			// must inspect the same durable attempt instead of running it again.
			if err = nc.PublishRequest(subject, "_INBOX.owned-unobserved-installation", data); err != nil {
				t.Fatal(err)
			}
			msg, err := nc.Request(subject, data, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			r, err := netbirdcommand.DecodeReceipt(msg.Data)
			if err != nil || !r.Matches(c) {
				t.Fatal("broker lost installation correlation", err)
			}
			if !enabledFixture {
				if r.Status != "rejected" || calls.Load() != 0 || j.State(time.Now()).Remaining != netbirdcommand.MaxJournalAttempts {
					t.Fatal("broker admitted an unsupported installer")
				}
				return
			}
			if r.Status != "unconfirmed" || calls.Load() != 1 {
				t.Fatal("lost reply repeated installation")
			}
			query := serviceControl(c, "receipt")
			query.Version, query.Revision, query.Operation = netbirdcommand.RecoveryVersion, c.Revision, c.Operation
			if got := sendServiceControl(t, nc, query); got.Receipt != r {
				t.Fatal("control lost installation evidence")
			}
			if released := sendServiceControl(t, nc, serviceControl(c, "release")); released.Outcome != "ok" || released.Receipt != r {
				t.Fatal("release rewrote installation uncertainty")
			}
		})
	}
}

func TestInstallationWithdrawalBeforeDeliveryPreventsExecution(t *testing.T) {
	e, j, c, _ := ownedInstallation(t)
	calls := 0
	e.install = func(context.Context, netbirdcommand.Command) error { calls++; return nil }
	q := serviceControl(c, "withdraw")
	q.Version, q.Revision, q.Operation = netbirdcommand.RecoveryVersion, c.Revision, c.Operation
	control, _ := netbirdcommand.EncodeControl(q)
	proof, err := j.Control(t.Context(), control)
	if err != nil || proof.Outcome != "ok" || proof.Receipt.Status != "withdrawn" {
		t.Fatal("installation withdrawal failed", err)
	}
	data, _ := netbirdcommand.Encode(c)
	got, err := e.Execute(t.Context(), data)
	if err != nil || got != proof.Receipt || calls != 0 {
		t.Fatal("withdrawn installation executed", err)
	}
	next := connectionAfterInstallation(c)
	next.RequestID = c.RequestID
	data, _ = netbirdcommand.Encode(next)
	if _, err = e.Execute(t.Context(), data); err == nil {
		t.Fatal("withdrawal UUID was reused by a connection command")
	}
}

func TestInstallationCannotBypassEarlierConnectionOrRegistrationAttempt(t *testing.T) {
	for _, operation := range []string{"up", "register"} {
		t.Run(operation, func(t *testing.T) {
			e, j, installation, _ := ownedInstallation(t)
			prior := connectionAfterInstallation(installation)
			if operation == "register" {
				prior.Version, prior.Operation, prior.SetupKey = netbirdcommand.RegistrationVersion, "register", "owned-key"
			}
			calls := 0
			e.run = func(context.Context, netbirdcommand.Command) error { return ErrActionUnconfirmed }
			e.install = func(context.Context, netbirdcommand.Command) error { calls++; return nil }
			data, _ := netbirdcommand.Encode(prior)
			result, err := e.Execute(t.Context(), data)
			if err != nil || result.Status != "unconfirmed" {
				t.Fatal("prior uncertainty was not retained", err)
			}
			before := j.State(time.Now())
			for _, reuseID := range []bool{false, true} {
				c := installation
				if reuseID {
					c.RequestID = prior.RequestID
				}
				data, _ := netbirdcommand.Encode(c)
				if _, err := e.Execute(t.Context(), data); err == nil {
					t.Fatal("installation bypassed earlier durable work")
				}
			}
			if calls != 0 || j.State(time.Now()) != before {
				t.Fatal("blocked installation mutated the journal")
			}
		})
	}
}
