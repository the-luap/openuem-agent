package netbird

import (
	"context"
	"errors"
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

func ownedDurable(t *testing.T) (*DurableExecutor, *netbirdjournal.Journal, netbirdcommand.Command, string) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	c := netbirdcommand.Command{Version: 1, Identity: netbirdcommand.Identity{DeviceID: "owned-device", TenantID: 1, SiteID: 1}, RequestID: uuid.NewString(), Revision: strings.Repeat("a", 64), Operation: "up", ManagementURL: "https://management.example.test", IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
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

func TestDurableNetbirdExecutesOnceWithCorrelatedReceipt(t *testing.T) {
	e, j, c, _ := ownedDurable(t)
	called := 0
	e.run = func(ctx context.Context, got netbirdcommand.Command) error {
		called++
		if got != c {
			t.Fatal("executor changed reviewed command")
		}
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(c.ExpiresAt) {
			t.Fatal("command expiry was not applied")
		}
		receipt, err := j.Lookup(c)
		if err != nil || receipt == nil || receipt.Status != "unconfirmed" {
			t.Fatal("CLI ran before durable attempt", err)
		}
		return nil
	}
	data, _ := netbirdcommand.Encode(c)
	first, err := e.Execute(t.Context(), data)
	if err != nil || first.Status != "completed" || !first.Matches(c) {
		t.Fatal("execution receipt did not correlate", err)
	}
	e.now = func() time.Time { return c.ExpiresAt.Add(time.Hour) }
	again, err := e.Execute(t.Context(), data)
	if err != nil || again != first || called != 1 {
		t.Fatal("completed command repeated or expired history changed", err)
	}
}

func TestDurableNetbirdCancellationAndCrashKeepUncertainty(t *testing.T) {
	e, j, c, path := ownedDurable(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	called := 0
	e.run = func(ctx context.Context, _ netbirdcommand.Command) error { called++; cancel(); return nil }
	data, _ := netbirdcommand.Encode(c)
	r, err := e.Execute(ctx, data)
	if err != nil || r.Status != "unconfirmed" {
		t.Fatal("cancelled execution claimed success", err)
	}
	j.Close()
	reopened, err := netbirdjournal.Open(path, strings.Repeat("b", 64), c.Identity, netbirdjournal.Boot{Platform: "linux", ID: "90000000-0000-4000-8000-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, _ := NewDurableExecutor(reopened)
	restarted.run = func(context.Context, netbirdcommand.Command) error { called++; return nil }
	r, err = restarted.Execute(t.Context(), data)
	if err != nil || r.Status != "unconfirmed" || called != 1 {
		t.Fatal("restart repeated uncertain execution", err)
	}
	next := c
	next.RequestID = uuid.NewString()
	raw, _ := netbirdcommand.Encode(next)
	if _, err = restarted.Execute(t.Context(), raw); err == nil || called != 1 {
		t.Fatal("unresolved command allowed a follow-up")
	}
}

func TestDurableNetbirdRefusesExpiredMalformedAndStoppedWork(t *testing.T) {
	e, j, c, _ := ownedDurable(t)
	called := 0
	e.run = func(context.Context, netbirdcommand.Command) error { called++; return nil }
	for _, raw := range [][]byte{nil, []byte(`{"management_url":"https://management.example.test"}`), []byte(`{"version":1}`)} {
		if _, err := e.Execute(t.Context(), raw); !errors.Is(err, ErrInvalidAction) {
			t.Fatal("legacy or invalid wire accepted", err)
		}
	}
	raw, _ := netbirdcommand.Encode(c)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.Execute(ctx, raw); err == nil {
		t.Fatal("stopped service admitted command")
	}
	e.now = func() time.Time { return c.ExpiresAt }
	if _, err := e.Execute(t.Context(), raw); err == nil {
		t.Fatal("expired command admitted")
	}
	receipt, err := j.Lookup(c)
	if err != nil || receipt != nil || called != 0 {
		t.Fatal("rejected work acquired an attempt", err)
	}
}

func TestDurableNetbirdConcurrentCommandCannotOverlap(t *testing.T) {
	e, _, c, _ := ownedDurable(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var called atomic.Int32
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	e.run = func(ctx context.Context, _ netbirdcommand.Command) error {
		called.Add(1)
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	raw, _ := netbirdcommand.Encode(c)
	done := make(chan error, 1)
	go func() { _, err := e.Execute(ctx, raw); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	next := c
	next.RequestID = uuid.NewString()
	data, _ := netbirdcommand.Encode(next)
	r, err := e.Execute(ctx, data)
	if err != nil || r.Status != "busy" || !r.Matches(next) {
		t.Fatal("overlapping command was not refused", err)
	}
	close(release)
	if err = <-done; err != nil || called.Load() != 1 {
		t.Fatal("overlapping execution", err)
	}
}

func TestDurableNetbirdResultWriteFailureDoesNotReturnSuccess(t *testing.T) {
	e, _, c, path := ownedDurable(t)
	e.run = func(context.Context, netbirdcommand.Command) error {
		return os.WriteFile(filepath.Join(path, "0001-result.json"), []byte("incomplete"), 0600)
	}
	data, _ := netbirdcommand.Encode(c)
	r, err := e.Execute(t.Context(), data)
	if err == nil || r.Status == "completed" {
		t.Fatal("failed receipt persistence returned success")
	}
}
