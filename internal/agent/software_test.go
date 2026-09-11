package agent

import (
	"bytes"
	"context"
	"crypto"
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

type softwareJournalFixture struct {
	entry                                    *enrollmentstore.SoftwareEntry
	failStart, failResult, commitBeforeError bool
}

func copySoftwareEntry(e *enrollmentstore.SoftwareEntry) *enrollmentstore.SoftwareEntry {
	if e == nil {
		return nil
	}
	copy := &enrollmentstore.SoftwareEntry{Task: e.Task, Nonce: bytes.Clone(e.Nonce), BootSession: e.BootSession}
	if e.Result != nil {
		data, _ := json.Marshal(e.Result)
		copy.Result = new(enrollment.SoftwareResult)
		_ = json.Unmarshal(data, copy.Result)
		clear(data)
	}
	return copy
}
func (j *softwareJournalFixture) Lookup(task enrollment.SoftwareTask) (*enrollmentstore.SoftwareEntry, error) {
	if j.entry != nil {
		a, _ := task.Digest()
		b, _ := j.entry.Task.Digest()
		if a != b {
			return nil, enrollmentstore.ErrUnavailable
		}
	}
	return copySoftwareEntry(j.entry), nil
}
func (j *softwareJournalFixture) Begin(task enrollment.SoftwareTask, secret *enrollment.SoftwareSecret) (bool, *enrollmentstore.SoftwareEntry, error) {
	return j.begin(task, secret, windowssoftware.BootSession{})
}
func (j *softwareJournalFixture) BeginWithBootSession(task enrollment.SoftwareTask, secret *enrollment.SoftwareSecret, boot windowssoftware.BootSession) (bool, *enrollmentstore.SoftwareEntry, error) {
	if !boot.Valid() {
		return false, nil, enrollmentstore.ErrUnavailable
	}
	return j.begin(task, secret, boot)
}
func (j *softwareJournalFixture) begin(task enrollment.SoftwareTask, secret *enrollment.SoftwareSecret, boot windowssoftware.BootSession) (bool, *enrollmentstore.SoftwareEntry, error) {
	if j.entry != nil {
		return false, copySoftwareEntry(j.entry), nil
	}
	if j.failStart && !j.commitBeforeError {
		return false, nil, enrollmentstore.ErrUnavailable
	}
	j.entry = &enrollmentstore.SoftwareEntry{Task: task, Nonce: secret.Nonce(), BootSession: boot}
	if j.failStart {
		return false, nil, enrollmentstore.ErrUnavailable
	}
	return true, copySoftwareEntry(j.entry), nil
}
func (j *softwareJournalFixture) RecordResult(result enrollment.SoftwareResult) error {
	if j.entry == nil || !result.Context.Equal(j.entry.Task.Context) {
		return enrollmentstore.ErrUnavailable
	}
	wire, _ := json.Marshal(result)
	defer clear(wire)
	if j.entry.Result != nil {
		previous, _ := json.Marshal(j.entry.Result)
		defer clear(previous)
		if bytes.Equal(wire, previous) {
			return nil
		}
		return enrollmentstore.ErrUnavailable
	}
	if j.failResult && !j.commitBeforeError {
		return enrollmentstore.ErrUnavailable
	}
	j.entry.Result = new(enrollment.SoftwareResult)
	_ = json.Unmarshal(wire, j.entry.Result)
	if j.failResult {
		return enrollmentstore.ErrUnavailable
	}
	return nil
}

type softwareRuntimeFixture struct {
	issuer                  crypto.Signer
	agent                   *Agent
	worker                  *nats.Conn
	client                  *softwareClient
	journal                 *softwareJournalFixture
	task                    *enrollment.SoftwareTask
	recipient               enrollment.SoftwareRecipient
	runs, reports, polls    int
	result                  *enrollment.SoftwareResult
	loseReply, wrongReceipt bool
	mu                      sync.Mutex
}

func newSoftwareRuntimeFixture(t *testing.T) *softwareRuntimeFixture {
	t.Helper()
	a, worker, _, issuer := nativeRuntimeFixtureWithIssuer(t)
	a.individual.identity.Platform = "windows"
	key, err := enrollment.NewSoftwareRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	j := new(softwareJournalFixture)
	r, err := newSoftwareClient(a.individual.identity, key, j, func() error { return nil })
	if err != nil {
		key.Close()
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	r.bootSession = func() (windowssoftware.BootSession, error) {
		return windowssoftware.BootSession{Sequence: 41, SystemProcessCreated: 130000000000000001}, nil
	}
	plan := enrollment.SoftwarePlan{Kind: "windows-msi", Operation: "install", Identifier: "Owned.RuntimeFixture", Version: "1.2.3", Architecture: "amd64", MinimumOS: "10.0.26100", Artifact: enrollment.SoftwareArtifact{URL: "https://packages.example.test/fixture.msi?token=private-source", SHA256: strings.Repeat("a", 64), Format: "msi"}, Detection: enrollment.SoftwareDetection{Kind: "msi-product", ProductCode: "{AABBCCDD-0000-4000-8000-000000000001}", Version: "1.2.3"}, MSIProperties: map[string]string{"LICENSEKEY": "private-license"}, SuccessCodes: []uint32{0}, RebootCodes: []uint32{3010}}
	hash, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f := &softwareRuntimeFixture{agent: a, worker: worker, client: r, journal: j, issuer: issuer, recipient: enrollment.SoftwareRecipient{ID: uuid.NewString(), Identity: r.scope, PublicKey: key.PublicKey()}}
	c := enrollment.SoftwareContext{Version: 1, Protocol: enrollment.SoftwareProtocol, Identity: r.scope, TaskID: uuid.NewString(), PreparationID: uuid.NewString(), RevisionID: uuid.NewString(), RecipientID: f.recipient.ID, PlanHash: hash, Expectation: plan.Expectation(), CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
	f.task, err = enrollment.SealSoftwareTask(f.recipient, c, plan, bytes.Repeat([]byte{7}, 32), r.authority, issuer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if j.entry != nil {
			j.entry.Close()
		}
		if f.result != nil {
			clear(f.result.Nonce)
		}
	})
	return f
}

func TestSoftwareClientRequiresNativeBootBeforeAdmission(t *testing.T) {
	for _, failure := range []string{"missing_reader", "read_error", "invalid", "changed_after_admission"} {
		t.Run(failure, func(t *testing.T) {
			f := newSoftwareRuntimeFixture(t)
			calls := 0
			f.client.bootSession = func() (windowssoftware.BootSession, error) {
				calls++
				if failure == "read_error" {
					return windowssoftware.BootSession{}, windowssoftware.ErrBootEvidence
				}
				if failure == "invalid" {
					return windowssoftware.BootSession{}, nil
				}
				boot := windowssoftware.BootSession{Sequence: 41, SystemProcessCreated: 130000000000000001}
				if calls > 1 {
					boot.Sequence++
					boot.SystemProcessCreated++
				}
				return boot, nil
			}
			if failure == "missing_reader" {
				f.client.bootSession = nil
			}
			if err := f.client.cycle(t.Context(), f.exchange(t), func(context.Context, enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
				t.Fatal("unverified boot admitted native installer")
				return softwareInterrupted()
			}); err == nil {
				t.Fatal("missing or changed boot accepted")
			}
			if (f.journal.entry != nil) != (failure == "changed_after_admission") {
				t.Fatal("invalid boot changed durable admission")
			}
			if f.journal.entry != nil && (f.journal.entry.BootSession.Sequence != 41 || f.journal.entry.Result != nil) {
				t.Fatal("changed boot rewrote admission history")
			}
		})
	}
}

func TestSoftwareClientRejectsBurnWithoutProfilePermission(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	for _, mode := range []string{"challenge", "recipient"} {
		calls := 0
		exchange := func(_ context.Context, data []byte) ([]byte, error) {
			calls++
			request, err := enrollment.DecodeSoftwareRequest(data, time.Now())
			if err != nil || request.Action != "challenge" || request.BurnVersion != 0 {
				t.Fatal("unverified capability advertised or signed", err)
			}
			reply := enrollment.SoftwareReply{Version: 1, Protocol: enrollment.SoftwareProtocol, OK: true}
			if mode == "challenge" {
				reply.Registration = &enrollment.SoftwareRegistration{Version: 1, Protocol: enrollment.SoftwareProtocol, Identity: f.client.scope, ID: f.recipient.ID, PublicKey: f.recipient.PublicKey, Nonce: bytes.Repeat([]byte{2}, 32), ExpiresAt: time.Now().Add(time.Minute).Unix(), BurnVersion: 1}
			} else {
				r := f.recipient
				r.BurnVersion = 1
				reply.Recipient = &r
			}
			return json.Marshal(reply)
		}
		if f.client.register(t.Context(), exchange) == nil || calls != 1 || f.client.recipientID != "" {
			t.Fatal("server introduced unrequested Burn support")
		}
	}
	secret, err := f.client.key.Open(*f.task, f.client.authority, f.client.scope, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := secret.Plan
	secret.Close()
	p.Kind, p.Artifact.Format, p.MSIProperties = "windows-burn", "exe", nil
	p.Artifact.URL = "https://example.invalid/fixture.exe"
	p.Arguments = []string{"/quiet", "/norestart"}
	p.Detection = enrollment.SoftwareDetection{Kind: "uninstall-key", UninstallKey: p.Detection.ProductCode, RegistryView: "64", Version: "1.2.3"}
	capable := f.recipient
	capable.BurnVersion = 1
	c := f.task.Context
	c.PlanHash, _ = p.Digest()
	c.Expectation = p.Expectation()
	f.task, err = enrollment.SealSoftwareTask(capable, c, p, bytes.Repeat([]byte{7}, 32), f.client.authority, f.issuer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	boots := 0
	f.client.bootSession = func() (windowssoftware.BootSession, error) {
		boots++
		return windowssoftware.BootSession{}, nil
	}
	if err := f.client.cycle(t.Context(), f.exchange(t), func(context.Context, enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
		t.Fatal("Burn reached native execution before capability acceptance")
		return softwareInterrupted()
	}); err == nil || f.journal.entry != nil || boots != 0 {
		t.Fatal("unverified Burn execution acquired durable admission", err)
	}
}
func (f *softwareRuntimeFixture) exchange(t *testing.T) recoveryExchange {
	t.Helper()
	subject, err := enrollment.RequestSubject(f.client.scope.AgentID, "software")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.worker.Subscribe(subject, func(message *nats.Msg) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !enrollment.ValidReply(f.client.scope.AgentID, message.Reply) || bytes.Contains(message.Data, []byte("private-")) {
			t.Error("private RPC leaked plan or used a foreign inbox")
			return
		}
		request, err := enrollment.DecodeSoftwareRequest(message.Data, time.Now())
		if err != nil {
			t.Error(err)
			return
		}
		reply := enrollment.SoftwareReply{Version: 1, Protocol: enrollment.SoftwareProtocol, OK: true}
		switch request.Action {
		case "challenge":
			reply.Registration = &enrollment.SoftwareRegistration{Version: 1, Protocol: enrollment.SoftwareProtocol, Identity: f.client.scope, ID: f.recipient.ID, PublicKey: f.recipient.PublicKey, Nonce: bytes.Repeat([]byte{2}, 32), ExpiresAt: time.Now().Add(time.Minute).Unix(), BurnVersion: f.recipient.BurnVersion}
		case "register":
			if enrollment.VerifySoftwareRegistration(*request.Registration, request.Signature, f.client.certificate, time.Now()) != nil {
				t.Error("invalid registration proof")
				return
			}
			reply.Recipient = &f.recipient
		case "poll":
			f.polls++
			reply.Task = f.task
		case "result":
			f.reports++
			if f.journal.entry == nil || f.journal.entry.Result == nil {
				t.Error("result sent before durable publication")
				return
			}
			if enrollment.VerifySoftwareResult(*request.Result, f.client.certificate, time.Now()) != nil || enrollment.VerifySoftwareSubmission(*request.Submission, *request.Result, f.client.scope, f.client.certificate, time.Now()) != nil {
				t.Error("invalid outcome/current submission proof")
				return
			}
			wire, _ := json.Marshal(request.Result)
			if f.result != nil {
				previous, _ := json.Marshal(f.result)
				if !bytes.Equal(previous, wire) {
					t.Error("retry changed original result")
				}
				clear(previous)
			}
			f.result = request.Result
			clear(wire)
			if f.loseReply {
				f.loseReply = false
				_ = message.Respond([]byte(`{"error":"owned lost reply"}`))
				return
			}
			reply.Receipt, err = enrollment.SoftwareResultReceipt(*request.Result, time.Now())
			if err != nil {
				t.Error(err)
				return
			}
			if f.wrongReceipt {
				reply.Receipt.ResultHash = strings.Repeat("b", 64)
			}
		default:
			t.Error("unexpected software action")
			return
		}
		wire, _ := json.Marshal(reply)
		_ = message.Respond(wire)
		clear(wire)
	})
	if err != nil || f.worker.FlushTimeout(time.Second) != nil {
		t.Fatal("software subscription", err)
	}
	return func(ctx context.Context, wire []byte) ([]byte, error) {
		message, err := f.agent.NATSConnection.RequestWithContext(ctx, subject, wire)
		if err != nil {
			return nil, err
		}
		return message.Data, nil
	}
}
func (f *softwareRuntimeFixture) execute(t *testing.T) softwareExecutor {
	return func(ctx context.Context, plan enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
		f.runs++
		if f.journal.entry == nil || f.journal.entry.Result != nil || plan.MSIProperties["LICENSEKEY"] != "private-license" {
			t.Error("executor lacked exact private plan and durable admission")
		}
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(time.Unix(f.task.Context.ExpiresAt, 0)) || deadline.After(f.client.certificate.NotAfter.Add(-30*time.Second)) {
			t.Error("unbounded installer lifetime")
		}
		zero := uint32(0)
		return enrollment.SoftwareOutcome{State: "observed", Execution: "started", ExitCode: &zero, Before: enrollment.SoftwareObservation{State: "absent"}, After: enrollment.SoftwareObservation{State: "present", Version: "1.2.3"}}
	}
}

func TestSoftwareRuntimeUsesPrivateWSSAndRetriesExactDurableReceipt(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	f.loseReply = true
	exchange, execute := f.exchange(t), f.execute(t)
	if err := f.client.cycle(t.Context(), exchange, execute); err == nil || f.client.pending == nil || !f.client.persisted {
		t.Fatal("lost reply discarded durable result")
	}
	if err := f.client.cycle(t.Context(), exchange, execute); err != nil || f.client.pending != nil {
		t.Fatal("receipt retry failed", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.runs != 1 || f.polls != 1 || f.reports != 2 {
		t.Fatal("retry repeated installer", f.runs, f.polls, f.reports)
	}
}

func TestSoftwareRuntimeLostIntentCommitRecoversUncertaintyWithoutExecution(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	f.journal.failStart, f.journal.commitBeforeError = true, true
	exchange, execute := f.exchange(t), f.execute(t)
	if err := f.client.cycle(t.Context(), exchange, execute); err == nil || f.runs != 0 {
		t.Fatal("lost commit admitted installer")
	}
	f.journal.failStart = false
	if err := f.client.cycle(t.Context(), exchange, execute); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.runs != 0 || f.result == nil || f.result.Outcome.State != "uncertain" || f.result.Outcome.Execution != "unknown" {
		t.Fatal("interrupted intent was rerun or declared successful")
	}
}

func TestSoftwareRuntimePersistsBeforeReportingAndRejectsWrongReceipt(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	f.journal.failResult = true
	exchange, execute := f.exchange(t), f.execute(t)
	if err := f.client.cycle(t.Context(), exchange, execute); err == nil || f.client.pending == nil || f.client.persisted {
		t.Fatal("failed storage sent or discarded result")
	}
	f.mu.Lock()
	reports := f.reports
	f.wrongReceipt = true
	f.mu.Unlock()
	if reports != 0 {
		t.Fatal("uncommitted result transmitted")
	}
	f.journal.failResult = false
	if err := f.client.cycle(t.Context(), exchange, execute); err == nil || f.client.pending == nil {
		t.Fatal("foreign receipt discarded result")
	}
	f.mu.Lock()
	f.wrongReceipt = false
	f.mu.Unlock()
	if err := f.client.cycle(t.Context(), exchange, execute); err != nil || f.runs != 1 {
		t.Fatal("receipt recovery repeated installer", err)
	}
}

func TestSoftwareRuntimeRejectsForgedCommandsBeforeJournalAndExecutor(t *testing.T) {
	for _, mutate := range []func(*enrollment.SoftwareTask){func(t *enrollment.SoftwareTask) { t.Signature[0] ^= 1 }, func(t *enrollment.SoftwareTask) { t.Context.Identity.SiteID++ }, func(t *enrollment.SoftwareTask) { t.Context.ExpiresAt = time.Now().Add(-time.Minute).Unix() }, func(t *enrollment.SoftwareTask) { t.Ciphertext[0] ^= 1 }} {
		f := newSoftwareRuntimeFixture(t)
		mutate(f.task)
		if err := f.client.cycle(t.Context(), f.exchange(t), f.execute(t)); err == nil || f.runs != 0 || f.journal.entry != nil {
			t.Fatal("untrusted command reached durable execution admission")
		}
	}
}

func TestSoftwareRuntimeCancellationPreservesUncertainResult(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	exchange := f.exchange(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	execute := f.execute(t)
	if err := f.client.cycle(ctx, exchange, func(ctx context.Context, p enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
		result := execute(ctx, p)
		cancel()
		return result
	}); err == nil {
		t.Fatal("cancelled network cycle succeeded")
	}
	if f.client.pending == nil || !f.client.persisted || f.client.pending.Outcome.State != "uncertain" {
		t.Fatal("cancelled execution lost uncertainty")
	}
	if err := f.client.cycle(t.Context(), exchange, execute); err != nil || f.runs != 1 {
		t.Fatal("restart repeated interrupted work", err)
	}
	f.client.live = func() error { return errors.New("owned lost lease") }
	if err := f.client.cycle(t.Context(), exchange, execute); err == nil {
		t.Fatal("lost service ownership continued execution")
	}
}
