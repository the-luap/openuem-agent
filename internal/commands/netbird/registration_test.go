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
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
)

func TestDurableRegistrationRetainsOnlyDigestAndDoesNotRepeat(t *testing.T) {
	e, j, c, path := ownedDurable(t)
	c.Version = netbirdcommand.RegistrationVersion
	c.Operation = "register"
	c.SetupKey = "owned-private-registration-key"
	calls := 0
	e.run = func(ctx context.Context, got netbirdcommand.Command) error {
		calls++
		if got.SetupKey != c.SetupKey || got != c {
			t.Error("registration lost its reviewed key or identity")
		}
		r, err := j.Lookup(c)
		if err != nil || r == nil || r.Status != "unconfirmed" {
			t.Error("registration ran before its permanent attempt")
		}
		return nil
	}
	data, err := netbirdcommand.Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	first, err := e.Execute(t.Context(), data)
	if err != nil || first.Status != "completed" || !first.Matches(c) {
		t.Fatal("registration result was not correlated", err)
	}
	changed := c
	changed.SetupKey = "another-owned-key"
	wrong, _ := netbirdcommand.Encode(changed)
	if _, err = e.Execute(t.Context(), wrong); err == nil {
		t.Fatal("retained request accepted a different key")
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
	restarted.run = func(context.Context, netbirdcommand.Command) error { calls++; return nil }
	again, err := restarted.Execute(t.Context(), data)
	if err != nil || again != first || calls != 1 {
		t.Fatal("restart repeated registration", err)
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
		if strings.Contains(string(body), c.SetupKey) || strings.Contains(string(body), "setup_key") {
			t.Fatal("journal persisted a registration credential")
		}
	}
}

func TestDurableServiceExplicitRegistrationReadinessAndControlRecovery(t *testing.T) {
	e, j, c, _ := ownedDurable(t)
	c.Version = netbirdcommand.RegistrationVersion
	c.Operation = "register"
	c.SetupKey = "owned-private-registration-key"
	nc := serviceBroker(t)
	service, err := NewDurableService(t.Context(), j, c.Identity, c.ExpiresAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	service.executor = e
	var calls atomic.Int64
	e.run = func(context.Context, netbirdcommand.Command) error { calls.Add(1); return ErrActionUnconfirmed }
	if err = service.Bind(nc); err != nil {
		t.Fatal(err)
	}
	control := serviceControl(c, "state")
	control.Kind = "registration-state"
	ready := sendServiceControl(t, nc, control)
	if ready.State.Status != "ready" || ready.Kind != "registration-state" {
		t.Fatal("registration support was not explicit")
	}
	data, _ := netbirdcommand.Encode(c)
	subject, _ := netbirdcommand.Subject(c.DeviceID)
	msg, err := nc.Request(subject, data, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := netbirdcommand.DecodeReceipt(msg.Data)
	if err != nil || receipt.Status != "unconfirmed" || !receipt.Matches(c) {
		t.Fatal("registration uncertainty was lost", err)
	}
	query := sendServiceControl(t, nc, serviceControl(c, "receipt"))
	if query.Receipt != receipt {
		t.Fatal("registration query lost its original evidence")
	}
	release := serviceControl(c, "release")
	release.RequestID = uuid.NewString()
	resolved := sendServiceControl(t, nc, release)
	if resolved.Outcome != "ok" || resolved.ReleaseID != release.RequestID || resolved.Receipt.Status != "unconfirmed" {
		t.Fatal("registration release lost its immutable outcome")
	}
	control = serviceControl(c, "state")
	control.Kind = "registration-state"
	ready = sendServiceControl(t, nc, control)
	if ready.State.Status != "ready" || calls.Load() != 1 {
		t.Fatal("release repeated registration or failed to restore admission")
	}
}
