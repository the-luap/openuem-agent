package netbird

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/netbirdcommand"
)

func TestDurableNetbirdBrokerResponseLossDoesNotRepeatExecution(t *testing.T) {
	e, _, c, _ := ownedDurable(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("owned broker did not start")
	}
	connection, err := nats.Connect(broker.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	entered, release, completed := make(chan struct{}), make(chan struct{}), make(chan struct{}, 2)
	var calls, legacyCalls atomic.Int32
	e.run = func(ctx context.Context, _ netbirdcommand.Command) error {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	subject, _ := netbirdcommand.Subject(c.DeviceID)
	_, err = connection.Subscribe("agent.netbird.up."+c.DeviceID, func(*nats.Msg) { legacyCalls.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	_, err = connection.QueueSubscribe(subject, "owned-netbird", func(msg *nats.Msg) {
		receipt, err := e.Execute(ctx, msg.Data)
		if err != nil {
			_ = msg.Respond(nil)
			return
		}
		body, err := netbirdcommand.EncodeReceipt(receipt)
		if err != nil {
			_ = msg.Respond(nil)
			return
		}
		_ = msg.Respond(body)
		completed <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	raw, _ := netbirdcommand.Encode(c)
	request, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	lost := make(chan error, 1)
	go func() { _, err := connection.RequestWithContext(request, subject, raw); lost <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancelRequest()
	if err = <-lost; !errors.Is(err, context.Canceled) {
		t.Fatal("owned caller did not lose its reply", err)
	}
	close(release)
	select {
	case <-completed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	replay, err := connection.RequestWithContext(ctx, subject, raw)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := netbirdcommand.DecodeReceipt(replay.Data)
	if err != nil || receipt.Status != "completed" || !receipt.Matches(c) || calls.Load() != 1 || legacyCalls.Load() != 0 {
		t.Fatal("response recovery repeated or misrouted execution", err)
	}
	select {
	case <-completed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
