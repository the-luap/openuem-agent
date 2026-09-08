package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/macsecurity"
)

// Runtime tests use a durable-in-fixture journal and an injected OS driver.
// Native keychain/DPAPI and actual subprocess boundaries have separate tests.
// Every journal operation verifies that the runtime holds its process lease.
type rotationJournalFixture struct {
	t                       *testing.T
	leased                  bool
	busy                    bool
	entries                 map[int]*enrollmentstore.RotationEntry
	failRecord              bool
	commitBeforeError       bool
	beginCalls, recordCalls int
}

func cloneRotationEntry(entry *enrollmentstore.RotationEntry) *enrollmentstore.RotationEntry {
	if entry == nil {
		return nil
	}
	copy := *entry
	copy.Nonce, copy.TaskDigest = bytes.Clone(entry.Nonce), bytes.Clone(entry.TaskDigest)
	if entry.Result != nil {
		wire, _ := json.Marshal(entry.Result)
		copy.Result = new(enrollment.RotationResult)
		_ = json.Unmarshal(wire, copy.Result)
	}
	return &copy
}

func (j *rotationJournalFixture) Lookup(c enrollment.RotationContext) (*enrollmentstore.RotationEntry, error) {
	if !j.leased {
		j.t.Error("journal lookup without process lease")
		return nil, enrollmentstore.ErrUnavailable
	}
	entry := j.entries[c.Ordinal]
	if entry != nil && entry.Context != c {
		return nil, enrollmentstore.ErrUnavailable
	}
	return cloneRotationEntry(entry), nil
}

func (j *rotationJournalFixture) Begin(task enrollment.RotationTask, nonce []byte) (bool, *enrollmentstore.RotationEntry, error) {
	j.beginCalls++
	entry, err := j.Lookup(task.Context)
	if err != nil {
		return false, nil, err
	}
	if entry != nil {
		return false, entry, nil
	}
	if !task.Valid(time.Now()) || len(nonce) != 32 {
		return false, nil, enrollmentstore.ErrUnavailable
	}
	wire, _ := json.Marshal(task)
	digest := sha256.Sum256(wire)
	entry = &enrollmentstore.RotationEntry{Context: task.Context, Nonce: bytes.Clone(nonce), TaskDigest: bytes.Clone(digest[:])}
	j.entries[task.Context.Ordinal] = entry
	return true, cloneRotationEntry(entry), nil
}

func (j *rotationJournalFixture) RecordResult(result enrollment.RotationResult) error {
	j.recordCalls++
	entry, err := j.Lookup(result.Context)
	if err != nil || entry == nil || !bytes.Equal(entry.Nonce, result.Nonce) {
		return enrollmentstore.ErrUnavailable
	}
	wire, _ := json.Marshal(result)
	if entry.Result != nil {
		previous, _ := json.Marshal(entry.Result)
		if bytes.Equal(previous, wire) {
			return nil
		}
		return enrollmentstore.ErrUnavailable
	}
	if j.failRecord && !j.commitBeforeError {
		return enrollmentstore.ErrUnavailable
	}
	entry.Result = new(enrollment.RotationResult)
	_ = json.Unmarshal(wire, entry.Result)
	j.entries[result.Context.Ordinal] = entry
	if j.failRecord {
		return enrollmentstore.ErrUnavailable
	}
	return nil
}

type rotationFixtureLease struct{ close func() }

func (l *rotationFixtureLease) Close() error {
	if l.close != nil {
		l.close()
		l.close = nil
	}
	return nil
}

type rotationFixtureResult struct {
	outcome string
	key     []byte
	closed  bool
}

func (r *rotationFixtureResult) Outcome() string { return r.outcome }
func (r *rotationFixtureResult) Key() []byte     { return r.key }
func (r *rotationFixtureResult) Close()          { clear(r.key); r.closed = true }

type rotationRuntimeFixture struct {
	agent     *Agent
	worker    *nats.Conn
	client    *rotationClient
	journal   *rotationJournalFixture
	recipient enrollment.RecoveryRecipient
	console   *enrollment.RecoveryRecipientKey
	task      *enrollment.RotationTask
	nonce     []byte
	runs      int
	borrowed  []byte
	local     *rotationFixtureResult
	runHook   func(context.Context)
}

func newRotationRuntimeFixture(t *testing.T) *rotationRuntimeFixture {
	t.Helper()
	a, worker, recovery, recipient := recoveryFixture(t)
	recovery.recipientID = recipient.ID
	console, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(console.Close)
	j := &rotationJournalFixture{t: t, entries: make(map[int]*enrollmentstore.RotationEntry)}
	f := &rotationRuntimeFixture{agent: a, worker: worker, recipient: recipient, console: console, journal: j, nonce: bytes.Repeat([]byte{6}, 32)}
	c := enrollment.RotationContext{Binding: enrollment.RecoveryContext{Version: 1, Identity: recipient.Identity, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: recipient.ID, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}, Ordinal: 1, EscrowID: uuid.NewString(), ReplyKey: hex.EncodeToString(console.PublicKey())}
	f.task, err = enrollment.EncryptRotationTask(recipient, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), f.nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.client = &rotationClient{recovery: recovery, journal: j}
	f.client.lease = func() (io.Closer, rotationRunner, error) {
		if j.busy || j.leased {
			return nil, nil, macsecurity.ErrRotationBusy
		}
		j.leased = true
		return &rotationFixtureLease{close: func() { j.leased = false }}, func(ctx context.Context, key []byte) rotationLocalResult {
			f.runs++
			f.borrowed = key
			entry := j.entries[f.task.Context.Ordinal]
			if !j.leased || entry == nil || entry.Result != nil || !bytes.Equal(key, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
				t.Error("driver ran without exclusive durable admission")
			}
			deadline, ok := ctx.Deadline()
			if !ok || deadline.After(time.Unix(f.task.Context.Binding.ExpiresAt, 0)) || deadline.After(recovery.certificate.NotAfter.Add(-enrollment.RotationReceiptGrace)) {
				t.Error("driver exceeded mutation or certificate deadline")
			}
			f.local = &rotationFixtureResult{outcome: "rotated", key: []byte("1111-2222-3333-4444-5555-6666")}
			if f.runHook != nil {
				f.runHook(ctx)
			}
			return f.local
		}, nil
	}
	t.Cleanup(f.client.clearPending)
	return f
}

func (f *rotationRuntimeFixture) register(_ context.Context, data []byte) ([]byte, error) {
	r, err := enrollment.DecodeRecoveryRequest(data, time.Now())
	if err != nil || r.Action != "challenge" || !bytes.Equal(r.PublicKey, f.recipient.PublicKey) {
		return nil, enrollment.ErrRecovery
	}
	return json.Marshal(enrollment.RecoveryReply{Version: 1, OK: true, Recipient: &f.recipient})
}

func (f *rotationRuntimeFixture) exchange(result func(*enrollment.RotationResult) error) recoveryExchange {
	return func(_ context.Context, data []byte) ([]byte, error) {
		r, err := enrollment.DecodeRotationRequest(data)
		if err != nil {
			return nil, err
		}
		reply := enrollment.RotationReply{Version: 1, Protocol: enrollment.RotationProtocol, OK: true}
		if r.Action == "poll" {
			reply.Task = f.task
		} else if r.Action == "result" {
			if result != nil {
				if err = result(r.Result); err != nil {
					return nil, err
				}
			}
		} else {
			return nil, enrollment.ErrRecovery
		}
		return json.Marshal(reply)
	}
}

func TestRotationRuntimePrivateTransportPersistsBeforeSendingAndRetriesOnlyReceipt(t *testing.T) {
	f := newRotationRuntimeFixture(t)
	subject, _ := enrollment.RequestSubject(f.recipient.Identity.AgentID, "rotation")
	certificate := f.client.recovery.certificate
	var mu sync.Mutex
	polls, reports := 0, 0
	var receipt []byte
	_, err := f.worker.Subscribe(subject, func(message *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		if !enrollment.ValidReply(f.recipient.Identity.AgentID, message.Reply) || bytes.Contains(message.Data, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) || bytes.Contains(message.Data, []byte("1111-2222-3333-4444-5555-6666")) {
			t.Error("rotation wire exposed a key or used a foreign inbox")
			return
		}
		request, err := enrollment.DecodeRotationRequest(message.Data)
		if err != nil {
			t.Error(err)
			return
		}
		reply := enrollment.RotationReply{Version: 1, Protocol: enrollment.RotationProtocol, OK: true}
		if request.Action == "poll" {
			polls++
			reply.Task = f.task
		} else {
			reports++
			if request.Result == nil || request.Result.Outcome != "rotated" || enrollment.VerifyRotationResult(*request.Result, certificate, time.Now()) != nil {
				t.Error("invalid signed rotation receipt")
				return
			}
			wire, _ := json.Marshal(request.Result)
			if receipt == nil {
				receipt = wire
				_ = message.Respond([]byte(`{"error":"lost acknowledgement"}`))
				return
			}
			if !bytes.Equal(receipt, wire) {
				t.Error("rotation retry regenerated its encrypted receipt")
			}
		}
		wire, _ := json.Marshal(reply)
		_ = message.Respond(wire)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.worker.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	exchange := func(ctx context.Context, data []byte) ([]byte, error) {
		request, _ := enrollment.DecodeRotationRequest(data)
		if request.Action == "result" {
			if f.journal.leased || f.journal.entries[1] == nil || f.journal.entries[1].Result == nil || !f.local.closed || !bytes.Equal(f.borrowed, make([]byte, 29)) {
				t.Fatal("network transmission preceded persistence, lease release or plaintext clearing")
			}
		}
		message, err := f.agent.NATSConnection.RequestWithContext(ctx, subject, data)
		if err != nil {
			return nil, err
		}
		return message.Data, nil
	}
	if err = f.client.cycle(t.Context(), f.register, exchange); err == nil || f.client.pending == nil || !f.client.persisted {
		t.Fatal("lost acknowledgement discarded durable result")
	}
	if err = f.client.cycle(t.Context(), f.register, exchange); err != nil || f.client.pending != nil {
		t.Fatal("receipt retry failed", err)
	}
	// Simulate a new runtime and another delivery of the original task. The
	// saved receipt must be replayed without decrypting/executing its old key.
	f.client = &rotationClient{recovery: f.client.recovery, journal: f.journal, lease: f.client.lease}
	if err = f.client.cycle(t.Context(), f.register, exchange); err != nil {
		t.Fatal("restart did not recover durable receipt", err)
	}
	if f.runs != 1 || f.journal.beginCalls != 1 {
		t.Fatal("retry or restart repeated a mutation", f.runs, f.journal.beginCalls)
	}
	mu.Lock()
	defer mu.Unlock()
	if polls != 2 || reports != 3 {
		t.Fatal("wrong private protocol lifecycle", polls, reports)
	}
	var result enrollment.RotationResult
	if json.Unmarshal(receipt, &result) != nil {
		t.Fatal("missing receipt")
	}
	hash := sha256.Sum256(f.nonce)
	key, err := f.console.OpenRotationResult(result, f.task.Context, hex.EncodeToString(hash[:]), f.client.recovery.certificate, time.Now())
	if err != nil || !bytes.Equal(key.Key(), []byte("1111-2222-3333-4444-5555-6666")) {
		t.Fatal("console could not decrypt returned key", err)
	}
	key.Close()
}

func TestRotationRuntimePersistsChangedKeyDespiteShutdownAndWriteFailures(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncommitted", true: "lost-confirmation"}[committed], func(t *testing.T) {
			f := newRotationRuntimeFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.journal.failRecord, f.journal.commitBeforeError = true, committed
			f.runHook = func(context.Context) { cancel() }
			reports := 0
			exchange := f.exchange(func(*enrollment.RotationResult) error { reports++; return nil })
			if err := f.client.cycle(ctx, f.register, exchange); err == nil || f.client.pending == nil || f.client.persisted {
				t.Fatal("failed persistence lost the changed key")
			}
			if reports != 0 || !f.local.closed || !bytes.Equal(f.borrowed, make([]byte, 29)) {
				t.Fatal("unpersisted key was transmitted or retained in plaintext")
			}
			before, _ := json.Marshal(f.client.pending)
			f.journal.failRecord = false
			if err := f.client.persistPending(); err != nil || !f.client.persisted {
				t.Fatal("shutdown could not retry encrypted publication", err)
			}
			after, _ := json.Marshal(f.journal.entries[1].Result)
			if !bytes.Equal(before, after) {
				t.Fatal("persistence retry changed encrypted key bytes")
			}
			if err := f.client.cycle(t.Context(), f.register, exchange); err != nil || reports != 1 || f.runs != 1 {
				t.Fatal("retry repeated mutation or failed delivery", err)
			}
		})
	}
}

func TestRotationRuntimeRecoversIntentOnlyAfterExcludingLiveOwner(t *testing.T) {
	f := newRotationRuntimeFixture(t)
	lease, _, err := f.client.lease()
	if err != nil {
		t.Fatal(err)
	}
	if admitted, _, err := f.journal.Begin(*f.task, f.nonce); err != nil || !admitted {
		t.Fatal(err)
	}
	lease.Close()
	f.task.Context.Binding.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	f.journal.entries[1].Context = f.task.Context
	reports := 0
	exchange := func(_ context.Context, data []byte) ([]byte, error) {
		request, err := enrollment.DecodeRotationRequest(data)
		if err != nil {
			return nil, err
		}
		reply := enrollment.RotationReply{Version: 1, Protocol: enrollment.RotationProtocol, OK: true}
		if request.Action == "poll" {
			reply.Receipt = &f.task.Context
		} else {
			reports++
			if request.Result.Outcome != "uncertain" || request.Result.NewKey != nil || enrollment.VerifyRotationResult(*request.Result, f.client.recovery.certificate, time.Now()) != nil {
				t.Error("intent recovery lost signed uncertainty")
			}
		}
		return json.Marshal(reply)
	}
	f.journal.busy = true
	if err := f.client.cycle(t.Context(), f.register, exchange); err != nil || f.journal.recordCalls != 0 || reports != 0 {
		t.Fatal("live owner was reported as crashed", err)
	}
	f.journal.busy = false
	if err := f.client.cycle(t.Context(), f.register, exchange); err != nil || reports != 1 || f.runs != 0 || f.journal.beginCalls != 1 {
		t.Fatal("interrupted attempt was rerun", err)
	}
}

func TestRotationRuntimeRejectsForeignTasksAndUnknownReceiptRequests(t *testing.T) {
	f := newRotationRuntimeFixture(t)
	for name, mutate := range map[string]func(*enrollment.RotationTask){
		"scope":     func(v *enrollment.RotationTask) { v.Context.Binding.Identity.SiteID++ },
		"recipient": func(v *enrollment.RotationTask) { v.Context.Binding.RecipientID = uuid.NewString() },
		"native":    func(v *enrollment.RotationTask) { v.Context.Binding.NativeID = uuid.NewString() },
		"ordinal":   func(v *enrollment.RotationTask) { v.Context.Ordinal++ },
		"expiry":    func(v *enrollment.RotationTask) { v.Context.Binding.ExpiresAt = time.Now().Add(-time.Minute).Unix() },
		"ciphertext": func(v *enrollment.RotationTask) {
			v.Envelope.Ciphertext = bytes.Clone(v.Envelope.Ciphertext)
			v.Envelope.Ciphertext[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := *f.task
			mutate(&bad)
			exchange := func(context.Context, []byte) ([]byte, error) {
				return json.Marshal(enrollment.RotationReply{Version: 1, Protocol: enrollment.RotationProtocol, OK: true, Task: &bad})
			}
			if err := f.client.cycle(t.Context(), f.register, exchange); err == nil || f.runs != 0 || f.journal.beginCalls != 0 {
				t.Fatal("foreign task reached durable admission", err)
			}
		})
	}
	exchange := func(context.Context, []byte) ([]byte, error) {
		return json.Marshal(enrollment.RotationReply{Version: 1, Protocol: enrollment.RotationProtocol, OK: true, Receipt: &f.task.Context})
	}
	if err := f.client.cycle(t.Context(), f.register, exchange); err == nil || f.runs != 0 || f.journal.recordCalls != 0 {
		t.Fatal("unknown receipt request invented execution evidence", err)
	}
}

func TestRotationRuntimeReservesCertificateGraceAndPreservesRetiredReceipts(t *testing.T) {
	f := newRotationRuntimeFixture(t)
	certificate := *f.client.recovery.certificate
	certificate.NotAfter = time.Now().Add(enrollment.RotationReceiptGrace - time.Second)
	f.client.recovery.certificate = &certificate
	var outcome string
	if err := f.client.cycle(t.Context(), f.register, f.exchange(func(result *enrollment.RotationResult) error { outcome = result.Outcome; return nil })); err != nil || outcome != "unavailable" || f.runs != 0 {
		t.Fatal("certificate reserve was consumed by mutation", outcome, err)
	}

	f = newRotationRuntimeFixture(t)
	if err := f.client.cycle(t.Context(), f.register, f.exchange(func(*enrollment.RotationResult) error { return errors.New("lost acknowledgement") })); err == nil || f.client.pending == nil {
		t.Fatal("fixture receipt not retained")
	}
	wire, _ := json.Marshal(f.journal.entries[1].Result)
	f.recipient.ID = uuid.NewString()
	exchange := func(context.Context, []byte) ([]byte, error) {
		t.Error("retired receipt retransmitted")
		return nil, enrollment.ErrRecovery
	}
	if err := f.client.cycle(t.Context(), f.register, exchange); err != nil || f.client.pending != nil || f.runs != 1 {
		t.Fatal("retired epoch triggered mutation or delivery", err)
	}
	saved, _ := json.Marshal(f.journal.entries[1].Result)
	if !bytes.Equal(wire, saved) {
		t.Fatal("recipient replacement erased the durable encrypted key")
	}
}

func TestRotationRuntimeRequiresExplicitCompatibleCapabilities(t *testing.T) {
	f := newRotationRuntimeFixture(t)
	runtime := f.agent.individual
	runtime.recovery, runtime.rotation = f.client.recovery, f.client
	// A cancelled runtime lets the real capability setter start/join its owned
	// goroutine without issuing any network request or local OS command.
	runtime.cancel()
	for _, tc := range []struct{ recovery, rotation, wantRecovery, wantRotation int }{
		{0, 0, 0, 0}, {0, 1, 0, 0}, {1, 0, 1, 0}, {1, 2, 1, 0}, {2, 1, 0, 0}, {1, 1, 1, 1},
	} {
		f.agent.setRecoveryCapabilities(tc.recovery, tc.rotation)
		runtime.work.Wait()
		if runtime.recoveryVersion.Load() != int32(tc.wantRecovery) || runtime.rotationVersion.Load() != int32(tc.wantRotation) {
			t.Fatal("incompatible/missing capability enabled recovery execution", tc)
		}
	}
	runtime.rotation = nil
	f.agent.setRecoveryCapabilities(1, 1)
	if runtime.rotationVersion.Load() != 0 {
		t.Fatal("missing protected journal enabled rotation")
	}
	runtime.recovery = nil
	f.agent.setRecoveryCapabilities(1, 1)
	if runtime.recoveryVersion.Load() != 0 || runtime.rotationVersion.Load() != 0 {
		t.Fatal("missing Mac recipient enabled recovery")
	}
	(&Agent{}).setRecoveryCapabilities(1, 1)
	if f.runs != 0 || f.journal.beginCalls != 0 {
		t.Fatal("capability negotiation directly admitted an OS mutation")
	}
}

func TestRotationRuntimePreservesCandidatesAndSignsConservativeOutcomes(t *testing.T) {
	for _, tc := range []struct{ local, key, want string }{
		{"unverified", "1111-2222-3333-4444-5555-6666", "unverified"},
		{"uncertain", "1111-2222-3333-4444-5555-6666", "unverified"},
		{"unknown", "1111-2222-3333-4444-5555-6666", "unverified"},
		{"rotated", "", "uncertain"}, {"unknown", "", "uncertain"},
		{"rotated", "invalid-candidate", "uncertain"},
		{"rotated", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF", "uncertain"},
		{"invalid", "", "invalid"}, {"unavailable", "", "unavailable"}, {"unsupported", "", "unsupported"},
	} {
		t.Run(tc.local+"/"+tc.want+"/"+strconv.Itoa(len(tc.key)), func(t *testing.T) {
			f := newRotationRuntimeFixture(t)
			f.runHook = func(context.Context) { clear(f.local.key); f.local.outcome, f.local.key = tc.local, []byte(tc.key) }
			var receipt *enrollment.RotationResult
			if err := f.client.cycle(t.Context(), f.register, f.exchange(func(result *enrollment.RotationResult) error { receipt = result; return nil })); err != nil {
				t.Fatal(err)
			}
			if receipt == nil || receipt.Outcome != tc.want || (receipt.NewKey != nil) != (tc.want == "unverified") || enrollment.VerifyRotationResult(*receipt, f.client.recovery.certificate, time.Now()) != nil {
				t.Fatal("candidate or conservative outcome was lost")
			}
			if !f.local.closed || !bytes.Equal(f.borrowed, make([]byte, 29)) {
				t.Fatal("driver result was not cleared")
			}
		})
	}
}
