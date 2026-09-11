package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/windowssoftware"
)

type softwareReconciliationJournalFixture struct {
	*softwareJournalFixture
	saved                       *enrollmentstore.SoftwareReconciliationEntry
	failRead, failSave, failAck bool
}

func copyReconciliationEntry(entry *enrollmentstore.SoftwareReconciliationEntry) *enrollmentstore.SoftwareReconciliationEntry {
	if entry == nil {
		return nil
	}
	result := &enrollmentstore.SoftwareReconciliationEntry{Task: entry.Task, Acknowledged: entry.Acknowledged}
	wire, _ := json.Marshal(entry.Result)
	_ = json.Unmarshal(wire, &result.Result)
	clear(wire)
	return result
}

func (j *softwareReconciliationJournalFixture) LookupSoftwareOriginal(task enrollment.SoftwareReconciliationTask) (*enrollmentstore.SoftwareEntry, error) {
	if j.failRead {
		return nil, enrollmentstore.ErrUnavailable
	}
	return copySoftwareEntry(j.entry), nil
}
func (j *softwareReconciliationJournalFixture) LookupSoftwareReconciliation(task enrollment.SoftwareReconciliationTask) (*enrollmentstore.SoftwareReconciliationEntry, error) {
	if j.saved != nil && !j.saved.Task.Context.Equal(task.Context) {
		return nil, enrollmentstore.ErrUnavailable
	}
	return copyReconciliationEntry(j.saved), nil
}
func (j *softwareReconciliationJournalFixture) NextSoftwareReconciliation() (*enrollmentstore.SoftwareReconciliationEntry, error) {
	if j.failRead {
		return nil, enrollmentstore.ErrUnavailable
	}
	if j.saved == nil || j.saved.Acknowledged {
		return nil, nil
	}
	return copyReconciliationEntry(j.saved), nil
}
func (j *softwareReconciliationJournalFixture) RecordSoftwareReconciliation(task enrollment.SoftwareReconciliationTask, result enrollment.SoftwareReconciliationResult) error {
	if j.failSave {
		return enrollmentstore.ErrUnavailable
	}
	if j.saved != nil {
		want, _ := json.Marshal(j.saved.Result)
		got, _ := json.Marshal(result)
		defer clear(want)
		defer clear(got)
		if !bytes.Equal(want, got) {
			return enrollmentstore.ErrUnavailable
		}
		return nil
	}
	j.saved = copyReconciliationEntry(&enrollmentstore.SoftwareReconciliationEntry{Task: task, Result: result})
	return nil
}
func (j *softwareReconciliationJournalFixture) AcknowledgeSoftwareReconciliation(receipt enrollment.SoftwareReceipt) error {
	if j.failAck || j.saved == nil {
		return enrollmentstore.ErrUnavailable
	}
	want, err := enrollment.SoftwareReconciliationReceipt(j.saved.Result, time.Now())
	if err != nil || receipt != *want {
		return enrollmentstore.ErrUnavailable
	}
	j.saved.Acknowledged = true
	return nil
}

type softwareReconciliationRuntimeFixture struct {
	*softwareRuntimeFixture
	journal               *softwareReconciliationJournalFixture
	reconciliation        *enrollment.SoftwareReconciliationTask
	observations          int
	received              *enrollment.SoftwareReconciliationResult
	mu                    sync.Mutex
	reports, polls        int
	loseReply, wrongReply bool
}

func newSoftwareReconciliationRuntimeFixture(t *testing.T) *softwareReconciliationRuntimeFixture {
	t.Helper()
	base := newSoftwareRuntimeFixture(t)
	f := &softwareReconciliationRuntimeFixture{softwareRuntimeFixture: base, journal: &softwareReconciliationJournalFixture{softwareJournalFixture: base.journal}}
	f.client.journal = f.journal
	secret, err := f.client.key.Open(*f.task, f.client.authority, f.client.scope, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	boot, err := f.client.bootSession()
	if err != nil {
		t.Fatal(err)
	}
	f.journal.entry = &enrollmentstore.SoftwareEntry{Task: *f.task, Nonce: secret.Nonce(), BootSession: boot}
	f.client.bootSession = func() (windowssoftware.BootSession, error) {
		return windowssoftware.BootSession{Sequence: boot.Sequence + 1, SystemProcessCreated: boot.SystemProcessCreated + 1}, nil
	}
	f.signReconciliation(t, time.Now(), time.Now().Add(5*time.Minute))
	t.Cleanup(func() {
		if f.journal.saved != nil {
			f.journal.saved.Close()
		}
		if f.received != nil {
			clear(f.received.OriginalNonce)
		}
	})
	return f
}

func (f *softwareReconciliationRuntimeFixture) signReconciliation(t *testing.T, created, deadline time.Time) {
	t.Helper()
	hash, _ := f.task.Digest()
	c := enrollment.SoftwareReconciliationContext{Version: 1, Protocol: enrollment.SoftwareReconciliationProtocol, Identity: f.client.scope, ID: uuid.NewString(), Original: f.task.Context, OriginalTaskHash: hash, CreatedAt: created.Unix(), ExpiresAt: deadline.Unix()}
	var err error
	f.reconciliation, err = enrollment.SignSoftwareReconciliationTask(c, f.client.authority, f.issuer, created)
	if err != nil {
		t.Fatal(err)
	}
}

func (f *softwareReconciliationRuntimeFixture) observe(t *testing.T) softwareObserver {
	return func(ctx context.Context, rule windowssoftware.Rule) (windowssoftware.Observation, error) {
		f.observations++
		d := f.task.Context.Expectation.Detection
		if rule != (windowssoftware.Rule{Kind: d.Kind, ProductCode: d.ProductCode, UninstallKey: d.UninstallKey, RegistryView: d.RegistryView, Version: d.Version}) || rule.Validate() != nil {
			t.Error("observation changed exact original detection")
		}
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(time.Unix(f.reconciliation.Context.ExpiresAt, 0)) || deadline.After(f.client.certificate.NotAfter.Add(-30*time.Second)) {
			t.Error("read-only work has no bounded lifetime")
		}
		return windowssoftware.Observation{State: windowssoftware.Present, Version: "1.2.3"}, nil
	}
}

func (f *softwareReconciliationRuntimeFixture) exchange(t *testing.T) recoveryExchange {
	t.Helper()
	subject, _ := enrollment.RequestSubject(f.client.scope.AgentID, "software")
	_, err := f.worker.Subscribe(subject, func(message *nats.Msg) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !enrollment.ValidReply(f.client.scope.AgentID, message.Reply) || bytes.Contains(message.Data, []byte("private-")) {
			t.Error("reconciliation used foreign reply or exposed executable plan")
			return
		}
		request, err := enrollment.DecodeSoftwareReconciliationRequest(message.Data, time.Now())
		if err != nil {
			t.Error(err)
			return
		}
		reply := enrollment.SoftwareReconciliationReply{Version: 1, Protocol: enrollment.SoftwareReconciliationProtocol, OK: true}
		switch request.Action {
		case "poll":
			f.polls++
			reply.Task = f.reconciliation
		case "result":
			f.reports++
			if f.journal.saved == nil {
				t.Error("read-only evidence submitted before durable publication")
				return
			}
			if enrollment.VerifySoftwareReconciliationResult(*request.Result, f.client.certificate, time.Now()) != nil || enrollment.VerifySoftwareReconciliationSubmission(*request.Submission, *request.Result, f.client.scope, f.client.certificate, time.Now()) != nil {
				t.Error("unverified reconciliation result or current proof")
				return
			}
			if f.received != nil {
				want, _ := json.Marshal(f.received)
				got, _ := json.Marshal(request.Result)
				if !bytes.Equal(want, got) {
					t.Error("retry changed signed observation")
				}
				clear(want)
				clear(got)
				clear(f.received.OriginalNonce)
			}
			f.received = request.Result
			if f.loseReply {
				f.loseReply = false
				_ = message.Respond([]byte(`{"error":"owned lost reply"}`))
				return
			}
			reply.Receipt, err = enrollment.SoftwareReconciliationReceipt(*request.Result, time.Now())
			if err != nil {
				t.Error(err)
				return
			}
			if f.wrongReply {
				reply.Receipt.ResultHash = strings.Repeat("b", 64)
			}
		default:
			t.Error("unexpected reconciliation action")
			return
		}
		wire, _ := json.Marshal(reply)
		_ = message.Respond(wire)
		clear(wire)
	})
	if err != nil || f.worker.FlushTimeout(time.Second) != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, wire []byte) ([]byte, error) {
		message, err := f.agent.NATSConnection.RequestWithContext(ctx, subject, wire)
		if err != nil {
			return nil, err
		}
		return message.Data, nil
	}
}

func TestSoftwareReconciliationClientBindsBootAndExactReadOnlyObservation(t *testing.T) {
	for _, state := range []string{"observed", "drifted", "unknown", "waiting_for_boot", "unavailable", "missing_original", "legacy_boot", "changed_boot", "malformed_observation"} {
		t.Run(state, func(t *testing.T) {
			f := newSoftwareReconciliationRuntimeFixture(t)
			observe := f.observe(t)
			want, reads := state, 1
			switch state {
			case "drifted":
				observe = func(context.Context, windowssoftware.Rule) (windowssoftware.Observation, error) {
					f.observations++
					return windowssoftware.Observation{State: windowssoftware.Absent}, nil
				}
			case "unknown":
				observe = func(context.Context, windowssoftware.Rule) (windowssoftware.Observation, error) {
					f.observations++
					return windowssoftware.Observation{State: windowssoftware.Unknown}, windowssoftware.ErrObservation
				}
			case "malformed_observation":
				want = "unknown"
				observe = func(context.Context, windowssoftware.Rule) (windowssoftware.Observation, error) {
					f.observations++
					return windowssoftware.Observation{State: windowssoftware.Present, Version: " bad "}, nil
				}
			case "waiting_for_boot":
				reads = 0
				f.client.bootSession = func() (windowssoftware.BootSession, error) { return f.journal.entry.BootSession, nil }
			case "unavailable":
				reads = 0
				f.client.bootSession = func() (windowssoftware.BootSession, error) {
					return windowssoftware.BootSession{}, windowssoftware.ErrBootEvidence
				}
			case "missing_original":
				want, reads = "unavailable", 0
				f.journal.entry.Close()
				f.journal.entry = nil
			case "legacy_boot":
				want, reads = "unavailable", 0
				f.journal.entry.BootSession = windowssoftware.BootSession{}
			case "changed_boot":
				want = "unavailable"
				count := uint32(0)
				f.client.bootSession = func() (windowssoftware.BootSession, error) {
					count++
					return windowssoftware.BootSession{Sequence: 41 + count, SystemProcessCreated: 130000000000000001 + uint64(count)}, nil
				}
			}
			if err := f.client.reconcile(t.Context(), f.exchange(t), observe); err != nil {
				t.Fatal(err)
			}
			if f.journal.saved == nil || !f.journal.saved.Acknowledged || f.journal.saved.Result.Outcome.State != want || f.observations != reads || f.runs != 0 {
				t.Fatal("read-only outcome or execution count differs", f.observations, reads)
			}
			if want == "unavailable" && len(f.journal.saved.Result.OriginalNonce) != 0 {
				t.Fatal("unavailable evidence exposed an original nonce")
			}
		})
	}
}

func TestSoftwareReconciliationClientPersistsBeforeSubmissionAndRetriesWithoutRead(t *testing.T) {
	for _, failure := range []string{"store", "reply", "wrong_receipt", "acknowledgement"} {
		t.Run(failure, func(t *testing.T) {
			f := newSoftwareReconciliationRuntimeFixture(t)
			exchange := f.exchange(t)
			f.journal.failSave, f.journal.failAck = failure == "store", failure == "acknowledgement"
			f.loseReply, f.wrongReply = failure == "reply", failure == "wrong_receipt"
			if err := f.client.reconcile(t.Context(), exchange, f.observe(t)); err == nil {
				t.Fatal("failed persistence or transport reported success")
			}
			if f.client.reconciliationPending == nil || f.observations != 1 || failure == "store" && f.reports != 0 {
				t.Fatal("failed receipt was lost or sent before storage")
			}
			f.journal.failSave, f.journal.failAck, f.wrongReply = false, false, false
			if err := f.client.reconcile(t.Context(), exchange, f.observe(t)); err != nil {
				t.Fatal(err)
			}
			if f.observations != 1 || !f.journal.saved.Acknowledged || f.client.reconciliationPending != nil {
				t.Fatal("retry repeated observation or lost acknowledgement")
			}
		})
	}
}

func TestSoftwareReconciliationClientRecoversExpiredReceiptBeforePolling(t *testing.T) {
	f := newSoftwareReconciliationRuntimeFixture(t)
	// The real signed receipt predates expiry; only the owned fixture clock used
	// for construction is historical. Recovery uses actual current time.
	created := time.Now().Add(-3 * time.Minute)
	// Keep the original authorization's immutable time ordering valid.
	original := *f.task
	original.Context.CreatedAt = created.Add(-time.Minute).Unix()
	secret, err := f.client.key.Open(*f.task, f.client.authority, f.client.scope, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	nonce := secret.Nonce()
	defer clear(nonce)
	f.task, err = enrollment.SealSoftwareTask(f.recipient, original.Context, secret.Plan, nonce, f.client.authority, f.issuer, created)
	if err != nil {
		t.Fatal(err)
	}
	f.journal.entry.Task = *f.task
	f.signReconciliation(t, created, created.Add(time.Minute))
	hash, _ := f.reconciliation.Digest()
	boot, _ := f.client.bootSession()
	outcome := enrollment.SoftwareReconciliationOutcome{State: "observed", Admission: f.journal.entry.BootSession, Current: boot, Observation: enrollment.SoftwareObservation{State: "present", Version: "1.2.3"}}
	result, err := enrollment.SignSoftwareReconciliationResult(f.reconciliation.Context, hash, nonce, outcome, f.client.certificate, f.client.identity.Keys.Certificate, created)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(result.OriginalNonce)
	if err = f.journal.RecordSoftwareReconciliation(*f.reconciliation, *result); err != nil {
		t.Fatal(err)
	}
	if err = f.client.reconcile(t.Context(), f.exchange(t), f.observe(t)); err != nil {
		t.Fatal(err)
	}
	if f.polls != 0 || f.observations != 0 || f.reports != 1 || !f.journal.saved.Acknowledged {
		t.Fatal("expired receipt depended on task delivery or another observation")
	}
}

func TestSoftwareReconciliationClientRejectsBadAuthorityScopeAndJournal(t *testing.T) {
	for _, mutation := range []string{"signature", "foreign_scope", "bad_original", "read_error", "expired"} {
		t.Run(mutation, func(t *testing.T) {
			f := newSoftwareReconciliationRuntimeFixture(t)
			switch mutation {
			case "signature":
				f.reconciliation.Signature[0] ^= 1
			case "foreign_scope":
				f.reconciliation.Context.Identity.AgentID = uuid.NewString()
			case "bad_original":
				f.journal.entry.Task.Signature[0] ^= 1
			case "read_error":
				f.journal.failRead = true
			case "expired":
				f.reconciliation.Context.ExpiresAt = time.Now().Add(-time.Second).Unix()
			}
			if err := f.client.reconcile(t.Context(), f.exchange(t), f.observe(t)); err == nil {
				t.Fatal("unverified observation accepted")
			}
			if f.observations != 0 || f.journal.saved != nil || f.reports != 0 {
				t.Fatal("unverified task produced observation evidence")
			}
		})
	}
}

func TestSoftwareReconciliationCancellationRetainsEvidenceBeforeJoinedStop(t *testing.T) {
	f := newSoftwareReconciliationRuntimeFixture(t)
	r := f.agent.individual
	r.software = f.client
	r.softwareReconciliationVersion.Store(enrollment.SoftwareReconciliationVersion)
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	_ = f.exchange(t)
	t.Cleanup(func() {
		r.cancel()
		select {
		case <-release:
		default:
			close(release)
		}
		r.work.Wait()
	})
	f.agent.startSoftwareConsumerWithObserver(func(context.Context, enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
		t.Error("read-only capability admitted an installer")
		return softwareInterrupted()
	}, func(ctx context.Context, rule windowssoftware.Rule) (windowssoftware.Observation, error) {
		close(started)
		<-ctx.Done()
		<-release
		if f.client.identity.Keys.Certificate == nil {
			t.Error("signer released before read-only helper stopped")
		}
		return windowssoftware.Observation{State: windowssoftware.Unknown}, ctx.Err()
	})
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("observation did not start")
	}
	go func() { f.agent.Stop(); close(done) }()
	select {
	case <-done:
		t.Fatal("read-only cancellation returned before helper joined")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("read-only cycle did not join")
	}
	if f.journal.saved == nil || f.journal.saved.Result.Outcome.State != "unknown" || f.journal.saved.Acknowledged || f.reports != 0 {
		t.Fatal("cancellation lost exact durable unknown observation")
	}
}

func TestSoftwareReconciliationClientReadsRemovalExpectation(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed", true: "still_present"}[present], func(t *testing.T) {
			f := newSoftwareReconciliationRuntimeFixture(t)
			secret, err := f.client.key.Open(*f.task, f.client.authority, f.client.scope, f.recipient.ID, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Close()
			plan := secret.Plan
			plan.Operation, plan.Artifact, plan.MSIProperties = "remove", enrollment.SoftwareArtifact{}, nil
			originalContext := f.task.Context
			originalContext.PlanHash, err = plan.Digest()
			if err != nil {
				t.Fatal(err)
			}
			originalContext.Expectation = plan.Expectation()
			nonce := secret.Nonce()
			defer clear(nonce)
			f.task, err = enrollment.SealSoftwareTask(f.recipient, originalContext, plan, nonce, f.client.authority, f.issuer, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			f.journal.entry.Task = *f.task
			f.signReconciliation(t, time.Now(), time.Now().Add(5*time.Minute))
			observe := f.observe(t)
			want := "drifted"
			if !present {
				want = "observed"
				observe = func(ctx context.Context, rule windowssoftware.Rule) (windowssoftware.Observation, error) {
					return windowssoftware.Observation{State: windowssoftware.Absent}, nil
				}
			}
			if err := f.client.reconcile(t.Context(), f.exchange(t), observe); err != nil {
				t.Fatal(err)
			}
			if f.journal.saved.Result.Outcome.State != want {
				t.Fatal("removal used install expectation")
			}
		})
	}
}

func TestSoftwareReconciliationCapabilityIsIndependentAndWindowsOnly(t *testing.T) {
	f := newSoftwareReconciliationRuntimeFixture(t)
	r := f.agent.individual
	r.software = f.client
	r.cancel()
	for _, versions := range [][2]int{{0, 1}, {1, 0}, {1, 2}, {0, -1}, {1, 1}, {0, 0}} {
		f.agent.setSoftwareCapabilities(versions[0], versions[1], 0)
		r.work.Wait()
		if (r.softwareVersion.Load() == 1) != (versions[0] == 1) || (r.softwareReconciliationVersion.Load() == 1) != (versions[1] == 1) {
			t.Fatal("capabilities were conflated")
		}
	}
	r.identity.Platform = "macos"
	f.agent.setSoftwareCapabilities(1, 1, 0)
	if r.softwareVersion.Load() != 0 || r.softwareReconciliationVersion.Load() != 0 {
		t.Fatal("Mac enabled Windows software")
	}
	r.identity.Platform = "windows"
	f.client.journal = f.softwareRuntimeFixture.journal
	f.agent.setSoftwareCapabilities(0, 1, 0)
	if r.softwareReconciliationVersion.Load() != 0 {
		t.Fatal("missing protected reconciliation journal enabled")
	}
	if f.observations != 0 || f.runs != 0 {
		t.Fatal("cancelled capability fixture started work")
	}
	if !errors.Is(f.client.reconcile(t.Context(), f.exchange(t), f.observe(t)), enrollment.ErrSoftware) {
		t.Fatal("unsupported journal accepted reconciliation")
	}
}
