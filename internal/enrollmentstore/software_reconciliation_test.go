package enrollmentstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

type softwareReconciliationFixture struct {
	*renewalFixture
	j      *SoftwareJournal
	key    *enrollment.SoftwareRecipientKey
	task   *enrollment.SoftwareTask
	secret *enrollment.SoftwareSecret
	boot   enrollment.SoftwareBootSession
}

func newSoftwareReconciliationFixture(t *testing.T, backend NativeBackend) *softwareReconciliationFixture {
	t.Helper()
	f := &softwareReconciliationFixture{renewalFixture: newRenewalFixture(t, backend, "windows"), boot: enrollment.SoftwareBootSession{Sequence: 31, SystemProcessCreated: 133000000000000000}}
	var err error
	f.j, err = f.store.OpenSoftwareJournal(f.original)
	if err != nil {
		t.Fatal(err)
	}
	f.key, err = f.store.LoadOrCreateSoftwareRecipient(f.original)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.key.Close)
	f.task, f.secret = softwareJournalTask(t, f.j, f.key, f.issuer)
	won, entry, err := f.j.BeginWithBootSession(*f.task, f.secret, f.boot)
	if err != nil || !won || entry == nil {
		t.Fatal("fixture admission failed", err)
	}
	defer entry.Close()
	if err = f.j.RecordResult(*softwareResult(t, f.j, f.original, *f.task, entry.Nonce, "uncertain")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *softwareReconciliationFixture) observation(t *testing.T, state string) (*enrollment.SoftwareReconciliationTask, *enrollment.SoftwareReconciliationResult) {
	t.Helper()
	hash, _ := f.task.Digest()
	c := enrollment.SoftwareReconciliationContext{Version: 1, Protocol: enrollment.SoftwareReconciliationProtocol, Identity: f.j.scope, ID: uuid.NewString(), Original: f.task.Context, OriginalTaskHash: hash, CreatedAt: f.now.Unix(), ExpiresAt: f.now.Add(5 * time.Minute).Unix()}
	task, err := enrollment.SignSoftwareReconciliationTask(c, f.issuer.ca, f.issuer.key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	outcome := enrollment.SoftwareReconciliationOutcome{State: state, Admission: f.boot, Current: enrollment.SoftwareBootSession{Sequence: 32, SystemProcessCreated: f.boot.SystemProcessCreated + 1}, Observation: enrollment.SoftwareObservation{State: "unknown"}}
	nonce := f.secret.Nonce()
	defer clear(nonce)
	switch state {
	case "observed":
		outcome.Observation = enrollment.SoftwareObservation{State: "present", Version: "1.2.3"}
	case "drifted":
		outcome.Observation = enrollment.SoftwareObservation{State: "absent"}
	case "waiting_for_boot":
		outcome.Current = f.boot
	case "unavailable":
		outcome.Admission, outcome.Current = enrollment.SoftwareBootSession{}, enrollment.SoftwareBootSession{}
		nonce = nil
	}
	hash, _ = task.Digest()
	result, err := enrollment.SignSoftwareReconciliationResult(task.Context, hash, nonce, outcome, f.j.certificate, f.original.Keys.Certificate, f.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(result.OriginalNonce) })
	return task, result
}

func (f *softwareReconciliationFixture) acknowledge(t *testing.T, result enrollment.SoftwareReconciliationResult) {
	t.Helper()
	receipt, err := enrollment.SoftwareReconciliationReceipt(result, f.now)
	if err != nil || f.j.AcknowledgeSoftwareReconciliation(*receipt) != nil {
		t.Fatal("receipt acknowledgement failed", err)
	}
}

func runDurableSoftwareReconciliation(t *testing.T, backend NativeBackend) {
	t.Helper()
	f := newSoftwareReconciliationFixture(t, backend)
	original, err := backend.Load(softwareRecord("result", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	task, result := f.observation(t, "observed")
	if err := f.j.RecordSoftwareReconciliation(*task, *result); err != nil {
		t.Fatal(err)
	}
	if err := f.j.RecordSoftwareReconciliation(*task, *result); err != nil {
		t.Fatal("exact result retry failed", err)
	}
	next, secret := softwareJournalTask(t, f.j, f.key, f.issuer)
	if won, _, err := f.j.BeginWithBootSession(*next, secret, result.Outcome.Current); won || err == nil {
		t.Fatal("unacknowledged result released reservation")
	}
	f.now = f.now.Add(10 * time.Minute)
	f.j, err = f.store.OpenSoftwareJournal(f.original)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.j.NextSoftwareReconciliation()
	if err != nil || pending == nil || !pending.Task.Context.Equal(task.Context) || pending.Acknowledged {
		t.Fatal("restart after expiry lost pending receipt", err)
	}
	defer pending.Close()
	want, _ := json.Marshal(result)
	got, _ := json.Marshal(pending.Result)
	defer clear(want)
	defer clear(got)
	if !bytes.Equal(want, got) {
		t.Fatal("receipt changed after expiry")
	}
	f.acknowledge(t, *result)
	f.acknowledge(t, *result)
	f.j, err = f.store.OpenSoftwareJournal(f.original)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := f.j.NextSoftwareReconciliation(); err != nil || pending != nil {
		t.Fatal("acknowledged history returned as pending", err)
	}
	next, secret = softwareJournalTask(t, f.j, f.key, f.issuer)
	won, entry, err := f.j.BeginWithBootSession(*next, secret, result.Outcome.Current)
	if err != nil || !won || entry == nil {
		t.Fatal("verified acknowledged observation did not release next admission", err)
	}
	entry.Close()
	retained, err := backend.Load(softwareRecord("result", 1))
	defer clear(retained)
	if err != nil || !bytes.Equal(original, retained) {
		t.Fatal("reconciliation rewrote original evidence", err)
	}
	if retained, err := f.j.LookupSoftwareReconciliation(*task); err != nil || retained == nil || !retained.Acknowledged {
		t.Fatal("history lookup lost acknowledged receipt", err)
	} else {
		retained.Close()
	}
}

func TestSoftwareReconciliationJournalDurableReceiptAndRelease(t *testing.T) {
	runDurableSoftwareReconciliation(t, newMemoryBackend(t))
}

func TestSoftwareReconciliationJournalRequiresDefiniteBootEvidence(t *testing.T) {
	for _, state := range []string{"observed", "drifted", "unknown", "waiting_for_boot", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			f := newSoftwareReconciliationFixture(t, newMemoryBackend(t))
			task, result := f.observation(t, state)
			if err := f.j.RecordSoftwareReconciliation(*task, *result); err != nil {
				t.Fatal(err)
			}
			f.acknowledge(t, *result)
			next, secret := softwareJournalTask(t, f.j, f.key, f.issuer)
			won, entry, err := f.j.BeginWithBootSession(*next, secret, f.boot)
			if entry != nil {
				entry.Close()
			}
			definite := state == "observed" || state == "drifted"
			if won != definite || (err == nil) != definite {
				t.Fatal("local reservation differs from verified observation", err)
			}
		})
	}
}

func TestSoftwareReconciliationJournalRejectsUnboundEvidence(t *testing.T) {
	for _, mutation := range []string{"nonce", "admission_boot", "original_hash", "signature", "task_signature", "receipt", "changed_result", "missing_original", "legacy_boot"} {
		t.Run(mutation, func(t *testing.T) {
			b := newMemoryBackend(t)
			f := newSoftwareReconciliationFixture(t, b)
			task, result := f.observation(t, "observed")
			switch mutation {
			case "nonce":
				result.OriginalNonce[0] ^= 1
			case "admission_boot":
				result.Outcome.Admission.Sequence--
			case "original_hash":
				task.Context.OriginalTaskHash = strings.Repeat("a", 64)
			case "signature":
				result.Signature[0] ^= 1
			case "task_signature":
				task.Signature[0] ^= 1
			case "missing_original":
				delete(b.records, softwareRecord("start", 1))
				delete(b.records, softwareRecord("result", 1))
			case "legacy_boot":
				fields, err := decodeFields(b.records[softwareRecord("start", 1)], softwareStartMagicV2, 5)
				if err != nil {
					t.Fatal(err)
				}
				b.records[softwareRecord("start", 1)], err = encodeFields(softwareStartMagic, fields[:4]...)
				if err != nil {
					t.Fatal(err)
				}
			case "receipt", "changed_result":
				if err := f.j.RecordSoftwareReconciliation(*task, *result); err != nil {
					t.Fatal(err)
				}
				if mutation == "receipt" {
					receipt, _ := enrollment.SoftwareReconciliationReceipt(*result, f.now)
					receipt.ResultHash = strings.Repeat("b", 64)
					if f.j.AcknowledgeSoftwareReconciliation(*receipt) == nil {
						t.Fatal("wrong receipt acknowledged")
					}
					return
				}
				result.Outcome.State, result.Outcome.Observation = "drifted", enrollment.SoftwareObservation{State: "absent"}
			}
			// For semantic mutations, use a valid device signature so the durable
			// original binding, not a broken signature alone, must reject them.
			if mutation == "nonce" || mutation == "admission_boot" || mutation == "changed_result" {
				var err error
				result, err = enrollment.SignSoftwareReconciliationResult(result.Context, result.TaskHash, result.OriginalNonce, result.Outcome, f.j.certificate, f.original.Keys.Certificate, f.now)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(result.OriginalNonce)
			}
			if f.j.RecordSoftwareReconciliation(*task, *result) == nil {
				t.Fatal("unbound or changed observation persisted")
			}
		})
	}
}

func TestSoftwareReconciliationJournalLostCommitAndConcurrentRetry(t *testing.T) {
	for _, stage := range []string{"reconciliation", "reconciliation-ack"} {
		t.Run(stage, func(t *testing.T) {
			b := newMemoryBackend(t)
			f := newSoftwareReconciliationFixture(t, b)
			task, result := f.observation(t, "observed")
			if stage == "reconciliation-ack" {
				if err := f.j.RecordSoftwareReconciliation(*task, *result); err != nil {
					t.Fatal(err)
				}
			}
			b.failCreate, b.commitBeforeError = softwareRecord(stage, 1), true
			receipt, _ := enrollment.SoftwareReconciliationReceipt(*result, f.now)
			var err error
			if stage == "reconciliation" {
				err = f.j.RecordSoftwareReconciliation(*task, *result)
			} else {
				err = f.j.AcknowledgeSoftwareReconciliation(*receipt)
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Fatal("lost durable response reported success", err)
			}
			b.failCreate = ""
			var journals []*SoftwareJournal
			for range 6 {
				j, err := f.store.OpenSoftwareJournal(f.original)
				if err != nil {
					t.Fatal(err)
				}
				journals = append(journals, j)
			}
			var wg sync.WaitGroup
			for _, j := range journals {
				wg.Go(func() {
					if err := j.RecordSoftwareReconciliation(*task, *result); err != nil {
						t.Error("concurrent exact receipt retry failed", err)
					}
					if err := j.AcknowledgeSoftwareReconciliation(*receipt); err != nil {
						t.Error("concurrent acknowledgement failed", err)
					}
				})
			}
			wg.Wait()
			if _, err := b.Load(softwareRecord("reconciliation", 2)); !errors.Is(err, ErrMissing) {
				t.Fatal("retry duplicated observation", err)
			}
		})
	}
}

func TestSoftwareReconciliationJournalRejectsPartialRestore(t *testing.T) {
	for _, mutation := range []string{"orphan_ack", "gap", "foreign_binding", "wrong_ordinal", "tampered_result", "tampered_ack", "bad_name"} {
		t.Run(mutation, func(t *testing.T) {
			b := newMemoryBackend(t)
			f := newSoftwareReconciliationFixture(t, b)
			task, result := f.observation(t, "observed")
			if err := f.j.RecordSoftwareReconciliation(*task, *result); err != nil {
				t.Fatal(err)
			}
			f.acknowledge(t, *result)
			name := softwareRecord("reconciliation", 1)
			switch mutation {
			case "orphan_ack":
				delete(b.records, name)
			case "gap":
				b.records[softwareRecord("reconciliation", 2)] = b.records[name]
				delete(b.records, name)
				delete(b.records, softwareRecord("reconciliation-ack", 1))
			case "foreign_binding", "wrong_ordinal", "tampered_result":
				fields, err := decodeFields(b.records[name], softwareReconciliationMagic, 4)
				if err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "foreign_binding":
					fields[0] = []byte("foreign installation")
				case "wrong_ordinal":
					fields[1] = []byte("2")
				case "tampered_result":
					fields[3] = append([]byte(" "), fields[3]...)
				}
				b.records[name], err = encodeFields(softwareReconciliationMagic, fields...)
				if err != nil {
					t.Fatal(err)
				}
			case "tampered_ack":
				b.records[softwareRecord("reconciliation-ack", 1)] = []byte("not an acknowledgement")
			case "bad_name":
				for _, name := range []string{"software-reconciliation-v1-0000", "software-reconciliation-v1-4097", "software-reconciliation-ack-v1-1", "Software-reconciliation-v1-0001"} {
					if validRecord(name) {
						t.Fatal("noncanonical name accepted")
					}
				}
				return
			}
			if _, err := f.store.OpenSoftwareJournal(f.original); err == nil {
				t.Fatal("damaged reconciliation journal reopened")
			}
		})
	}
}

func TestSoftwareReconciliationJournalRenewalPreservesUnacknowledgedEvidence(t *testing.T) {
	f := newSoftwareReconciliationFixture(t, newMemoryBackend(t))
	task, result := f.observation(t, "observed")
	if err := f.j.RecordSoftwareReconciliation(*task, *result); err != nil {
		t.Fatal(err)
	}
	prepared, err := f.store.prepareRenewal(t.Context(), f.prepare)
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.store.confirmRenewal(t.Context(), prepared.ID, f.confirm)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if _, err := f.j.NextSoftwareReconciliation(); err == nil {
		t.Fatal("retired journal returned work")
	}
	if f.j.RecordSoftwareReconciliation(*task, *result) == nil {
		t.Fatal("retired journal wrote evidence")
	}
	j, err := f.store.OpenSoftwareJournal(current)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := j.NextSoftwareReconciliation()
	if err != nil || pending == nil {
		t.Fatal("renewal lost original signed observation", err)
	}
	defer pending.Close()
	proof, err := enrollment.SignSoftwareReconciliationSubmission(pending.Result, j.scope, j.certificate, current.Keys.Certificate, f.now)
	if err != nil || enrollment.VerifySoftwareReconciliationSubmission(*proof, *result, j.scope, j.certificate, f.now) != nil {
		t.Fatal("current generation could not submit historical receipt", err)
	}
	receipt, _ := enrollment.SoftwareReconciliationReceipt(*result, f.now)
	if j.AcknowledgeSoftwareReconciliation(*receipt) != nil {
		t.Fatal("current generation could not acknowledge historical observation")
	}
	if j.RecordSoftwareReconciliation(*task, *result) == nil {
		t.Fatal("current generation wrote new evidence for retired task")
	}
}

func TestSoftwareReconciliationJournalRejectsLostReleaseBehindLaterSuccess(t *testing.T) {
	b := newMemoryBackend(t)
	f := newSoftwareReconciliationFixture(t, b)
	task, result := f.observation(t, "observed")
	if err := f.j.RecordSoftwareReconciliation(*task, *result); err != nil {
		t.Fatal(err)
	}
	f.acknowledge(t, *result)
	next, secret := softwareJournalTask(t, f.j, f.key, f.issuer)
	won, entry, err := f.j.BeginWithBootSession(*next, secret, result.Outcome.Current)
	if err != nil || !won || entry == nil {
		t.Fatal(err)
	}
	defer entry.Close()
	if err = f.j.RecordResult(*softwareResult(t, f.j, f.original, *next, entry.Nonce, "observed")); err != nil {
		t.Fatal(err)
	}
	delete(b.records, softwareRecord("reconciliation-ack", 1))
	if _, err := f.store.OpenSoftwareJournal(f.original); err == nil {
		t.Fatal("later success concealed missing release evidence")
	}
	third, secret := softwareJournalTask(t, f.j, f.key, f.issuer)
	if won, entry, err := f.j.BeginWithBootSession(*third, secret, result.Outcome.Current); won || entry != nil || err == nil {
		t.Fatal("live journal ignored missing historical release")
	}
}
