package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/macsecurity"
)

func recoveryFixture(t *testing.T) (*Agent, *nats.Conn, *recoveryClient, enrollment.RecoveryRecipient) {
	t.Helper()
	a, worker, _ := nativeRuntimeFixture(t)
	a.individual.identity.Platform = "macos"
	key, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	r, err := newRecoveryClient(a.individual.identity, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	return a, worker, r, enrollment.RecoveryRecipient{ID: uuid.NewString(), Identity: r.scope, PublicKey: key.PublicKey()}
}

func recoveryTaskFixture(t *testing.T, recipient enrollment.RecoveryRecipient) *enrollment.RecoveryTask {
	t.Helper()
	c := enrollment.RecoveryContext{Version: 1, Identity: recipient.Identity, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: recipient.ID, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
	task, err := enrollment.EncryptRecoveryTask(recipient, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), bytes.Repeat([]byte{1}, 32), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestRecoveryRuntimeUsesPrivateWSSAndRetriesOnlySignedReceipt(t *testing.T) {
	a, worker, r, recipient := recoveryFixture(t)
	task := recoveryTaskFixture(t, recipient)
	challenge := enrollment.RecoveryRegistration{Version: 1, Identity: r.scope, ID: recipient.ID, PublicKey: recipient.PublicKey, Nonce: bytes.Repeat([]byte{2}, 32), ExpiresAt: time.Now().Add(time.Minute).Unix()}
	var mu sync.Mutex
	var receipt []byte
	registered, polls, reports := false, 0, 0
	subject, _ := enrollment.RequestSubject(r.scope.AgentID, "recovery")
	_, err := worker.Subscribe(subject, func(message *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		if !enrollment.ValidReply(r.scope.AgentID, message.Reply) || bytes.Contains(message.Data, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
			t.Error("private RPC leaked a key or used a foreign reply")
			return
		}
		request, err := enrollment.DecodeRecoveryRequest(message.Data, time.Now())
		if err != nil {
			t.Error(err)
			return
		}
		reply := enrollment.RecoveryReply{Version: 1, OK: true}
		switch request.Action {
		case "challenge":
			if registered {
				reply.Recipient = &recipient
			} else {
				reply.Registration = &challenge
			}
		case "register":
			if request.Registration == nil || enrollment.VerifyRecoveryRegistration(*request.Registration, request.Signature, r.certificate, time.Now()) != nil {
				t.Error("invalid registration proof")
				return
			}
			registered = true
			reply.Recipient = &recipient
		case "poll":
			polls++
			reply.Task = task
		case "result":
			reports++
			if request.Result == nil || request.Result.Outcome != "valid" || enrollment.VerifyRecoveryResult(*request.Result, r.certificate, time.Now()) != nil {
				t.Error("invalid outcome signature")
				return
			}
			data, _ := json.Marshal(request.Result)
			if receipt == nil {
				receipt = data
				message.Respond([]byte(`{"error":"reply lost"}`))
				return
			}
			if !bytes.Equal(data, receipt) {
				t.Error("retry changed the signed result")
			}
		default:
			t.Error("unexpected RPC action")
		}
		data, _ := json.Marshal(reply)
		message.Respond(data)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	exchange := func(ctx context.Context, data []byte) ([]byte, error) {
		message, err := a.NATSConnection.RequestWithContext(ctx, subject, data)
		if err != nil {
			return nil, err
		}
		return message.Data, nil
	}
	checks := 0
	var borrowed []byte
	validate := func(ctx context.Context, key []byte) (bool, error) {
		checks++
		borrowed = key
		if !bytes.Equal(key, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
			t.Error("wrong decrypted key")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 15*time.Second {
			t.Error("unbounded local validation")
		}
		return true, nil
	}
	if err = r.cycle(t.Context(), exchange, validate); err == nil || r.pending == nil {
		t.Fatal("failed response discarded retry proof")
	}
	if !bytes.Equal(borrowed, make([]byte, 29)) {
		t.Fatal("plaintext survived the local check")
	}
	if err = r.cycle(t.Context(), exchange, validate); err != nil || r.pending != nil {
		t.Fatal("receipt retry failed", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if polls != 1 || checks != 1 || reports != 2 || !registered {
		t.Fatal("receipt retry repeated local validation", polls, checks, reports)
	}
}

func TestRecoveryRuntimeSignsDistinctOutcomesAndRejectsForeignTasks(t *testing.T) {
	_, _, r, recipient := recoveryFixture(t)
	r.recipientID = recipient.ID
	for _, tc := range []struct {
		name    string
		valid   bool
		err     error
		outcome string
	}{
		{"invalid", false, nil, "invalid"}, {"unavailable", true, errors.New("private tool output must not escape"), "unavailable"}, {"unsupported", false, macsecurity.ErrUnsupported, "unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task := recoveryTaskFixture(t, recipient)
			var result *enrollment.RecoveryResult
			exchange := func(_ context.Context, data []byte) ([]byte, error) {
				request, err := enrollment.DecodeRecoveryRequest(data, time.Now())
				if err != nil {
					return nil, err
				}
				reply := enrollment.RecoveryReply{Version: 1, OK: true}
				if request.Action == "poll" {
					reply.Task = task
				} else if request.Action == "result" {
					result = request.Result
				} else {
					t.Error("unexpected RPC")
				}
				return json.Marshal(reply)
			}
			if err := r.cycle(t.Context(), exchange, func(context.Context, []byte) (bool, error) { return tc.valid, tc.err }); err != nil {
				t.Fatal(err)
			}
			if result == nil || result.Outcome != tc.outcome || enrollment.VerifyRecoveryResult(*result, r.certificate, time.Now()) != nil {
				t.Fatal("local outcome lost authenticity")
			}
		})
	}
	for _, mutate := range []func(*enrollment.RecoveryTask){
		func(t *enrollment.RecoveryTask) { t.Context.Identity.SiteID++ }, func(t *enrollment.RecoveryTask) { t.Context.RecipientID = uuid.NewString() },
		func(t *enrollment.RecoveryTask) { t.Context.KeyID = uuid.NewString() }, func(t *enrollment.RecoveryTask) { t.Context.ExpiresAt = time.Now().Add(-time.Second).Unix() },
		func(t *enrollment.RecoveryTask) { t.Ciphertext[0] ^= 1 },
	} {
		task := recoveryTaskFixture(t, recipient)
		mutate(task)
		exchange := func(context.Context, []byte) ([]byte, error) {
			return json.Marshal(enrollment.RecoveryReply{Version: 1, OK: true, Task: task})
		}
		if err := r.cycle(t.Context(), exchange, func(context.Context, []byte) (bool, error) {
			t.Error("foreign task reached local check")
			return true, nil
		}); err == nil {
			t.Fatal("foreign task accepted")
		}
	}
}

func TestRecoveryRuntimeDoesNotSignSubstitutedRegistration(t *testing.T) {
	_, _, r, recipient := recoveryFixture(t)
	for _, mutate := range []func(*enrollment.RecoveryRegistration){
		func(c *enrollment.RecoveryRegistration) { c.Identity.TenantID++ },
		func(c *enrollment.RecoveryRegistration) { c.PublicKey = make([]byte, 32) },
		func(c *enrollment.RecoveryRegistration) { c.ExpiresAt = time.Now().Add(-time.Second).Unix() },
	} {
		challenge := enrollment.RecoveryRegistration{Version: 1, Identity: r.scope, ID: recipient.ID, PublicKey: recipient.PublicKey, Nonce: bytes.Repeat([]byte{2}, 32), ExpiresAt: time.Now().Add(time.Minute).Unix()}
		mutate(&challenge)
		calls := 0
		exchange := func(context.Context, []byte) ([]byte, error) {
			calls++
			return json.Marshal(enrollment.RecoveryReply{Version: 1, OK: true, Registration: &challenge})
		}
		if err := r.register(t.Context(), exchange); err == nil || calls != 1 || r.recipientID != "" {
			t.Fatal("substituted challenge was signed")
		}
	}
}

func TestRecoveryRuntimeDiscardsExpiredOrReplacedRecipientReceipts(t *testing.T) {
	_, _, r, recipient := recoveryFixture(t)
	for _, expired := range []bool{false, true} {
		task := recoveryTaskFixture(t, recipient)
		secret, err := r.key.Open(*task, r.scope, recipient.ID, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		r.pending, err = secret.Result("valid", r.certificate, r.identity.Keys.Certificate, time.Now())
		secret.Close()
		if err != nil {
			t.Fatal(err)
		}
		oldNonce := r.pending.Nonce
		current := recipient
		if expired {
			r.pending.Context.ExpiresAt = time.Now().Add(-time.Second).Unix()
		} else {
			current.ID = uuid.NewString()
		}
		r.recipientID = ""
		exchange := func(_ context.Context, data []byte) ([]byte, error) {
			request, err := enrollment.DecodeRecoveryRequest(data, time.Now())
			if err != nil {
				return nil, err
			}
			reply := enrollment.RecoveryReply{Version: 1, OK: true}
			switch request.Action {
			case "challenge":
				reply.Recipient = &current
			case "poll":
				if request.RecipientID != current.ID {
					t.Error("poll retained retired recipient")
				}
			default:
				t.Error("retired result was retransmitted")
			}
			return json.Marshal(reply)
		}
		if err = r.cycle(t.Context(), exchange, func(context.Context, []byte) (bool, error) {
			t.Error("missing task reached validator")
			return false, nil
		}); err != nil {
			t.Fatal(err)
		}
		if r.pending != nil || !bytes.Equal(oldNonce, make([]byte, 32)) {
			t.Fatal("retired receipt was retained")
		}
	}
}
