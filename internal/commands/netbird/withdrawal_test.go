package netbird

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
)

func recoveryServiceControl(c netbirdcommand.Command, kind string) netbirdcommand.ControlRequest {
	r := serviceControl(c, kind)
	r.Version = netbirdcommand.RecoveryVersion
	r.Revision, r.Operation = c.Revision, c.Operation
	return r
}

func TestDurableServiceWithdrawalSurvivesLostReplyAndLateDelivery(t *testing.T) {
	for _, operation := range []string{"register", "up", "down", "switchprofile"} {
		t.Run(operation, func(t *testing.T) { exerciseDurableServiceWithdrawal(t, operation) })
	}
}

func exerciseDurableServiceWithdrawal(t *testing.T, operation string) {
	t.Helper()
	e, j, c, path := ownedDurable(t)
	c.Operation = operation
	if operation == "register" {
		c.Version = netbirdcommand.RegistrationVersion
		c.SetupKey = "owned-private-registration-key"
	}
	if operation == "switchprofile" {
		c.Profile = "owned-profile"
	}
	nc := serviceBroker(t)
	s, err := NewDurableService(t.Context(), j, c.Identity, c.ExpiresAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.executor = e
	var calls atomic.Int64
	e.run = func(context.Context, netbirdcommand.Command) error { calls.Add(1); return nil }
	if err = s.Bind(nc); err != nil {
		t.Fatal(err)
	}
	if r := sendServiceControl(t, nc, recoveryServiceControl(c, "receipt")); r.Outcome != "missing" {
		t.Fatal("fresh journal invented execution")
	}
	withdraw := recoveryServiceControl(c, "withdraw")
	wire, _ := netbirdcommand.EncodeControl(withdraw)
	subject, _ := netbirdcommand.ControlSubject(c.DeviceID)
	// The broker delivers the control, but no subscriber receives its response.
	if err = nc.PublishRequest(subject, "owned.withdrawal.unobserved", wire); err != nil {
		t.Fatal(err)
	}
	if err = nc.Flush(); err != nil {
		t.Fatal(err)
	}
	proof := sendServiceControl(t, nc, recoveryServiceControl(c, "receipt"))
	if proof.Outcome != "ok" || proof.Receipt.Status != "withdrawn" || proof.ReleaseID != withdraw.RequestID {
		t.Fatal("lost response erased withdrawal")
	}
	retry := recoveryServiceControl(c, "withdraw")
	retry.RequestID = withdraw.RequestID
	if proof := sendServiceControl(t, nc, retry); proof.Outcome != "ok" || proof.ReleaseID != withdraw.RequestID || proof.Receipt.Status != "withdrawn" {
		t.Fatal("fresh control lost permanent withdrawal identity")
	}
	data, _ := netbirdcommand.Encode(c)
	commandSubject, _ := netbirdcommand.Subject(c.DeviceID)
	msg, err := nc.Request(commandSubject, data, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := netbirdcommand.DecodeReceipt(msg.Data)
	if err != nil || receipt.Status != "withdrawn" || !receipt.Matches(c) || calls.Load() != 0 {
		t.Fatal("late broker delivery executed", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := netbirdjournal.Open(path, strings.Repeat("b", 64), c.Identity, netbirdjournal.Boot{Platform: "linux", ID: "90000000-0000-4000-8000-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	restarted, err := NewDurableExecutor(other)
	if err != nil {
		t.Fatal(err)
	}
	restarted.run = e.run
	receipt, err = restarted.Execute(t.Context(), data)
	if err != nil || receipt.Status != "withdrawn" || calls.Load() != 0 {
		t.Fatal("restart executed withdrawn command", err)
	}
}
