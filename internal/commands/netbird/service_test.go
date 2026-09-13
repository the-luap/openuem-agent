package netbird

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
)

func serviceBroker(t *testing.T) *nats.Conn {
	t.Helper()
	b, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	b.Start()
	t.Cleanup(func() { b.Shutdown(); b.WaitForShutdown() })
	if !b.ReadyForConnections(5 * time.Second) {
		t.Fatal("owned broker not ready")
	}
	nc, err := nats.Connect(b.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func serviceControl(c netbirdcommand.Command, kind string) netbirdcommand.ControlRequest {
	now := time.Now().UTC()
	r := netbirdcommand.ControlRequest{Version: 1, Identity: c.Identity, RequestID: uuid.NewString(), Kind: kind, IssuedAt: now, ExpiresAt: now.Add(5 * time.Second)}
	if kind != "state" {
		r.ReferenceID = c.RequestID
		r.CommandHash, _ = c.Digest()
	}
	return r
}

func sendServiceControl(t *testing.T, nc *nats.Conn, c netbirdcommand.ControlRequest) netbirdcommand.ControlResponse {
	t.Helper()
	data, err := netbirdcommand.EncodeControl(c)
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := netbirdcommand.ControlSubject(c.DeviceID)
	msg, err := nc.Request(subject, data, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := netbirdcommand.DecodeControlResponse(msg.Data, c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDurableServiceLostReplyRecoveryAndConnectionReplacement(t *testing.T) {
	e, j, c, _ := ownedDurable(t)
	nc := serviceBroker(t)
	s, err := NewDurableService(t.Context(), j, c.Identity, c.ExpiresAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.executor = e
	if err = s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	if err = s.Bind(nc); err != nil {
		t.Fatal("same connection rebound", err)
	}
	if r := sendServiceControl(t, nc, serviceControl(c, "state")); r.State.Status != "ready" {
		t.Fatal("journal was not ready")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	e.run = func(ctx context.Context, _ netbirdcommand.Command) error {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return errors.New("owned uncertain execution")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	subject, _ := netbirdcommand.Subject(c.DeviceID)
	data, _ := netbirdcommand.Encode(c)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	lost := make(chan error, 1)
	go func() { _, err := nc.RequestWithContext(ctx, subject, data); lost <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("command not admitted")
	}
	if r := sendServiceControl(t, nc, serviceControl(c, "state")); r.State.Status != "busy" || r.State.CanRelease {
		t.Fatal("live executor did not hold barrier")
	}
	if r := sendServiceControl(t, nc, serviceControl(c, "release")); r.Outcome != "blocked" {
		t.Fatal("live executor released")
	}
	cancel()
	if err = <-lost; !errors.Is(err, context.Canceled) {
		t.Fatal("reply was not lost", err)
	}
	close(release)
	// The second callback is serialized behind the first command and reads its
	// permanent receipt; it must not execute the command again.
	msg, err := nc.Request(subject, data, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := netbirdcommand.DecodeReceipt(msg.Data)
	if err != nil || !r.Matches(c) || r.Status != "unconfirmed" || calls.Load() != 1 {
		t.Fatal("lost reply repeated execution", err)
	}
	resolution := serviceControl(c, "release")
	controlSubject, _ := netbirdcommand.ControlSubject(c.DeviceID)
	raw, _ := netbirdcommand.EncodeControl(resolution)
	// Publish a reply inbox with no listener. The next control query is ordered
	// after this release on the same subscription and recovers its identity.
	if err = nc.PublishRequest(controlSubject, nats.NewInbox(), raw); err != nil {
		t.Fatal(err)
	}
	query := sendServiceControl(t, nc, serviceControl(c, "receipt"))
	if query.Outcome != "ok" || query.ReleaseID != resolution.RequestID || query.Receipt.Status != "unconfirmed" {
		t.Fatal("release response loss discarded evidence")
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
	state := sendServiceControl(t, nc, serviceControl(c, "state")).State
	if state.Status != "ready" || state.Remaining != netbirdjournal.MaxAttempts-1 {
		t.Fatal("connection change reset journal")
	}
	msg, err = nc.Request(subject, data, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err = netbirdcommand.DecodeReceipt(msg.Data)
	if err != nil || r.Status != "unconfirmed" || calls.Load() != 1 {
		t.Fatal("connection change repeated command", err)
	}
}

func TestDurableServiceCloseJoinsExecutionBeforeJournalLeaseRelease(t *testing.T) {
	e, j, c, path := ownedDurable(t)
	nc := serviceBroker(t)
	s, err := NewDurableService(t.Context(), j, c.Identity, c.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	s.executor = e
	entered, release, cancelled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.run = func(ctx context.Context, _ netbirdcommand.Command) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return nil
	}
	if err = s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	subject, _ := netbirdcommand.Subject(c.DeviceID)
	data, _ := netbirdcommand.Encode(c)
	if err = nc.PublishRequest(subject, nats.NewInbox(), data); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("command not admitted")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel command")
	}
	select {
	case <-closed:
		t.Fatal("journal closed before command joined")
	default:
	}
	if r, err := j.Lookup(c); err != nil || r == nil {
		t.Fatal("journal closed while executor remained live")
	}
	other, err := netbirdjournal.Open(path, strings.Repeat("b", 64), c.Identity, netbirdjournal.Boot{Platform: "linux", ID: "90000000-0000-4000-8000-000000000001"})
	if err == nil {
		other.Close()
		t.Fatal("service released its lease before command joined")
	}
	close(release)
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	other, err = netbirdjournal.Open(path, strings.Repeat("b", 64), c.Identity, netbirdjournal.Boot{Platform: "linux", ID: "90000000-0000-4000-8000-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	r, err := other.Lookup(c)
	if err != nil || r == nil || r.Status != "unconfirmed" {
		t.Fatal("shutdown invented success or lost result", err)
	}
	if err = s.Bind(nc); err == nil {
		t.Fatal("closed service rebound")
	}
}

func TestDurableServiceRejectsExpiredForeignAndMalformedCommands(t *testing.T) {
	e, j, c, _ := ownedDurable(t)
	nc := serviceBroker(t)
	s, err := NewDurableService(t.Context(), j, c.Identity, c.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.executor = e
	var calls atomic.Int32
	e.run = func(context.Context, netbirdcommand.Command) error { calls.Add(1); return nil }
	if err = s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	subject, _ := netbirdcommand.Subject(c.DeviceID)
	for _, mutate := range []func(*netbirdcommand.Command){
		func(c *netbirdcommand.Command) { c.SiteID++ },
		func(c *netbirdcommand.Command) {
			c.ExpiresAt = c.IssuedAt.Add(-time.Second)
			c.IssuedAt = c.IssuedAt.Add(-time.Minute)
		},
		func(c *netbirdcommand.Command) { c.ExpiresAt = c.ExpiresAt.Add(time.Second) },
	} {
		v := c
		mutate(&v)
		data, err := netbirdcommand.Encode(v)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := nc.Request(subject, data, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = netbirdcommand.DecodeReceipt(msg.Data); err == nil {
			t.Fatal("rejected command claimed execution evidence")
		}
	}
	msg, err := nc.Request(subject, []byte(`{"OneOffKey":"private"}`), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(msg.Data), "private") {
		t.Fatal("rejection exposed command data")
	}
	if calls.Load() != 0 || j.State(time.Now()).Remaining != netbirdjournal.MaxAttempts {
		t.Fatal("invalid command consumed an attempt")
	}
	if _, err = NewDurableService(nil, j, c.Identity, c.ExpiresAt); err == nil {
		t.Fatal("nil service lifetime accepted")
	}
	if _, err = NewDurableService(t.Context(), j, c.Identity, time.Now().Add(-time.Second)); err == nil {
		t.Fatal("expired certificate accepted")
	}
}
