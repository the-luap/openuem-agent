package netbirdjournal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
)

func withdrawalRequest(c netbirdcommand.Command, kind string) netbirdcommand.ControlRequest {
	v := controlRequest(c, kind)
	v.Version = netbirdcommand.RecoveryVersion
	v.Revision, v.Operation = c.Revision, c.Operation
	return v
}

func TestWithdrawalPermanentlyRejectsLateDeliveryAndRetainsProof(t *testing.T) {
	c := testCommand()
	c.Version, c.Operation, c.Profile, c.SetupKey = netbirdcommand.RegistrationVersion, "register", "", "owned-private-registration-key"
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	before := j.State(time.Now())
	if r := runControl(t, j, withdrawalRequest(c, "receipt")); r.Outcome != "missing" {
		t.Fatal("invented evidence")
	}
	if after := j.State(time.Now()); after != before {
		t.Fatal("query mutated journal")
	}
	control := withdrawalRequest(c, "withdraw")
	r := runControl(t, j, control)
	if r.Outcome != "ok" || r.Receipt.Status != "withdrawn" || r.ReleaseID != control.RequestID {
		t.Fatal("withdrawal lacks proof", r)
	}
	for _, now := range []time.Time{time.Now(), c.ExpiresAt.Add(time.Hour)} {
		admitted, receipt, err := j.Begin(c, now)
		if err != nil || admitted || receipt == nil || receipt.Status != "withdrawn" {
			t.Fatal("late delivery was admitted", err)
		}
	}
	changed := c
	changed.SetupKey = "another-key"
	if _, _, err := j.Begin(changed, time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatal("withdrawn UUID reused for another command", err)
	}
	if r := runControl(t, j, control); r.Outcome != "ok" {
		t.Fatal("same withdrawal lost identity")
	}
	if r := runControl(t, j, withdrawalRequest(c, "withdraw")); r.Outcome != "conflict" {
		t.Fatal("withdrawal identity replaced")
	}
	if r := runControl(t, j, controlRequest(c, "receipt")); r.Outcome != "conflict" {
		t.Fatal("legacy query claimed withdrawal support")
	}
	after := j.State(time.Now())
	if after.Status != "ready" || after.Remaining != MaxAttempts-1 || after.Revision == before.Revision {
		t.Fatal("withdrawal lost capacity or revision")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openTest(t, path, c, testBoot())
	r = runControl(t, j, withdrawalRequest(c, "receipt"))
	if r.Outcome != "ok" || r.ReleaseID != control.RequestID || r.Receipt.Status != "withdrawn" {
		t.Fatal("reopen lost withdrawal")
	}
	if receipt, err := j.Lookup(c); err != nil || receipt == nil || receipt.Status != "withdrawn" {
		t.Fatal("lookup lost permanent denial", err)
	}
	data, err := os.ReadFile(filepath.Join(path, withdrawalName(1)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), c.SetupKey) || strings.Contains(string(data), c.ManagementURL) {
		t.Fatal("withdrawal persisted a command secret")
	}
	next := c
	next.RequestID = uuid.NewString()
	beginTest(t, j, next)
}

func TestWithdrawalCannotRewriteAnyExecutionAttempt(t *testing.T) {
	for _, status := range []string{"active", "completed", "unconfirmed", "released"} {
		t.Run(status, func(t *testing.T) {
			c := testCommand()
			j := openTest(t, filepath.Join(t.TempDir(), "journal"), c, testBoot())
			beginTest(t, j, c)
			if status != "active" {
				result := status
				if result == "released" {
					result = "unconfirmed"
				}
				if _, err := j.Finish(c, result, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if status == "released" {
				if err := j.Release(c.RequestID, mustDigest(c), uuid.NewString(), time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if r := runControl(t, j, withdrawalRequest(c, "withdraw")); r.Outcome != "conflict" {
				t.Fatal("execution was converted into withdrawal")
			}
			if len(j.withdrawals) != 0 {
				t.Fatal("attempted command gained a tombstone")
			}
		})
	}
}

func TestWithdrawalAndExecutionAdmissionAreAtomic(t *testing.T) {
	for n := 0; n < 40; n++ {
		c := testCommand()
		j := openTest(t, filepath.Join(t.TempDir(), "journal"), c, testBoot())
		control := withdrawalRequest(c, "withdraw")
		wire, _ := netbirdcommand.EncodeControl(control)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var admitted bool
		var receipt *netbirdcommand.Receipt
		var beginErr, controlErr error
		var proof netbirdcommand.ControlResponse
		go func() { defer wg.Done(); <-start; admitted, receipt, beginErr = j.Begin(c, time.Now()) }()
		go func() { defer wg.Done(); <-start; proof, controlErr = j.Control(context.Background(), wire) }()
		close(start)
		wg.Wait()
		if beginErr != nil || controlErr != nil || !proof.Matches(control) {
			t.Fatal("race lost valid outcome", beginErr, controlErr)
		}
		if admitted {
			if receipt != nil || proof.Outcome != "conflict" || len(j.withdrawals) != 0 {
				t.Fatal("withdrawal overlapped admitted execution")
			}
		} else {
			if receipt == nil || receipt.Status != "withdrawn" || proof.Outcome != "ok" || len(j.entries) != 0 {
				t.Fatal("withdrawal allowed a later attempt")
			}
		}
		j.Close()
	}
}

func TestWithdrawalRespectsPendingCapacityClockAndPublication(t *testing.T) {
	for _, mode := range []string{"pending", "full", "clock", "publication", "expired", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			c := testCommand()
			path := filepath.Join(t.TempDir(), "journal")
			j := openTest(t, path, c, testBoot())
			control := withdrawalRequest(c, "withdraw")
			ctx := context.Background()
			switch mode {
			case "pending":
				other := c
				other.RequestID = uuid.NewString()
				beginTest(t, j, other)
			case "full":
				for n := 0; n < MaxAttempts; n++ {
					j.withdrawals[uuid.NewString()] = &withdrawal{}
				}
			case "clock":
				j.clock = time.Now().Add(time.Hour)
			case "publication":
				if err := os.WriteFile(filepath.Join(path, withdrawalName(1)), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "expired":
				control.IssuedAt = time.Now().Add(-time.Minute)
				control.ExpiresAt = control.IssuedAt.Add(time.Second)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			wire, _ := netbirdcommand.EncodeControl(control)
			r, err := j.Control(ctx, wire)
			if err == nil && r.Outcome == "ok" {
				t.Fatal("ineligible withdrawal produced proof")
			}
			if j.withdrawals[c.RequestID] != nil {
				t.Fatal("failed withdrawal admitted")
			}
			if mode == "publication" {
				if j.State(time.Now()).Status != "unavailable" {
					t.Fatal("publication failure did not poison journal")
				}
				j.Close()
				if other, err := Open(path, strings.Repeat("b", 64), c.Identity, testBoot()); err == nil {
					other.Close()
					t.Fatal("partial publication became empty history")
				}
			}
		})
	}
}

func TestWithdrawalReopenRequiresCanonicalBoundMetadata(t *testing.T) {
	for _, mode := range []string{"device", "filename", "extra", "status", "duplicate-attempt"} {
		t.Run(mode, func(t *testing.T) {
			c := testCommand()
			path := filepath.Join(t.TempDir(), "journal")
			j := openTest(t, path, c, testBoot())
			control := withdrawalRequest(c, "withdraw")
			runControl(t, j, control)
			name := withdrawalName(1)
			if mode == "duplicate-attempt" { // Individually valid files cannot claim both histories.
				value := start{RequestID: c.RequestID, DeviceID: c.DeviceID, Revision: c.Revision, CommandHash: mustDigest(c), Operation: c.Operation, IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, RecordedAt: c.IssuedAt, Boot: testBoot()}
				if err := j.files.create(recordName(1, "start"), value); err != nil {
					t.Fatal(err)
				}
			}
			j.Close()
			data, err := os.ReadFile(filepath.Join(path, name))
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "device":
				data = []byte(strings.Replace(string(data), c.DeviceID, "other-device", 1))
			case "filename":
				if err := os.Rename(filepath.Join(path, name), filepath.Join(path, withdrawalName(2))); err != nil {
					t.Fatal(err)
				}
			case "extra":
				data = []byte(strings.Replace(string(data), `"WithdrawalID":`, `"unknown":true,"WithdrawalID":`, 1))
			case "status":
				data = []byte(strings.Replace(string(data), `"status":"withdrawn"`, `"status":"completed"`, 1))
			}
			if mode != "filename" {
				if err := os.WriteFile(filepath.Join(path, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if other, err := Open(path, strings.Repeat("b", 64), c.Identity, testBoot()); err == nil {
				other.Close()
				t.Fatal("invalid withdrawal reopened")
			}
		})
	}
}

func TestWithdrawalUsesCurrentCertificateWithoutChangingOriginalReference(t *testing.T) {
	c := testCommand()
	c.DeviceID = uuid.NewString()
	c.Individual = true
	c.CertificateHash = strings.Repeat("c", 64)
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	control := withdrawalRequest(c, "withdraw")
	runControl(t, j, control)
	j.Close()
	current := c
	current.CertificateHash = strings.Repeat("d", 64)
	j = openTest(t, path, current, testBoot())
	query := withdrawalRequest(c, "receipt")
	wire, _ := netbirdcommand.EncodeControl(query)
	if _, err := j.Control(t.Context(), wire); err == nil {
		t.Fatal("retired certificate accessed journal")
	}
	query.Identity = current.Identity
	proof := runControl(t, j, query)
	if proof.Receipt.CommandHash != mustDigest(c) || proof.ReleaseID != control.RequestID || proof.CertificateHash != current.CertificateHash {
		t.Fatal("renewal changed original withdrawal reference")
	}
	if _, _, err := j.Begin(current, time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatal("renewal reused withdrawn command UUID", err)
	}
}

func TestMissingWithdrawalCannotBecomeAnEmptySlotBeforeLaterExecution(t *testing.T) {
	c := testCommand()
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	runControl(t, j, withdrawalRequest(c, "withdraw"))
	next := c
	next.RequestID = uuid.NewString()
	beginTest(t, j, next)
	if _, err := j.Finish(next, "completed", time.Now()); err != nil {
		t.Fatal(err)
	}
	j.Close()
	j = openTest(t, path, c, testBoot())
	j.Close()
	if err := os.Remove(filepath.Join(path, withdrawalName(1))); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(path, strings.Repeat("b", 64), c.Identity, testBoot()); err == nil {
		other.Close()
		t.Fatal("missing withdrawal was treated as an empty journal slot")
	}
}
