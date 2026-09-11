package enrollmentstore

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
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/windowssoftware"
)

func softwareFixture(t *testing.T, backend NativeBackend) (*Store, *Identity, *SoftwareJournal, *enrollment.SoftwareTask, *enrollment.SoftwareSecret) {
	t.Helper()
	s := &Store{backend: backend}
	b := testBootstrap()
	issuer := newFixtureIssuer(t)
	i, err := s.enroll(t.Context(), b, func(_ context.Context, r enrollment.Request) (*enrollment.Response, error) {
		return issuer.claim(b.Origin, r)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { i.Close() })
	j, err := s.OpenSoftwareJournal(i)
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.LoadOrCreateSoftwareRecipient(i)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	task, secret := softwareJournalTask(t, j, key, issuer)
	return s, i, j, task, secret
}

func softwareJournalTask(t *testing.T, j *SoftwareJournal, key *enrollment.SoftwareRecipientKey, issuer *fixtureIssuer) (*enrollment.SoftwareTask, *enrollment.SoftwareSecret) {
	t.Helper()
	plan := enrollment.SoftwarePlan{Kind: "windows-msi", Operation: "install", Identifier: "Owned.JournalFixture", Version: "1.2.3", Architecture: "amd64", MinimumOS: "10.0.26100", Artifact: enrollment.SoftwareArtifact{URL: "https://packages.example.test/owned.msi?token=private-source", SHA256: strings.Repeat("a", 64), Format: "msi"}, MSIProperties: map[string]string{"LICENSEKEY": "private-license"}, Detection: enrollment.SoftwareDetection{Kind: "msi-product", ProductCode: "{AABBCCDD-0000-4000-8000-000000000001}", Version: "1.2.3"}, SuccessCodes: []uint32{0}, RebootCodes: []uint32{3010}}
	hash, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	now := j.store.renewalTime()
	c := enrollment.SoftwareContext{Version: 1, Protocol: enrollment.SoftwareProtocol, Identity: j.scope, TaskID: uuid.NewString(), PreparationID: uuid.NewString(), RevisionID: uuid.NewString(), RecipientID: uuid.NewString(), PlanHash: hash, Expectation: plan.Expectation(), CreatedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix()}
	task, err := enrollment.SealSoftwareTask(enrollment.SoftwareRecipient{ID: c.RecipientID, Identity: c.Identity, PublicKey: key.PublicKey()}, c, plan, bytes.Repeat([]byte{7}, 32), issuer.ca, issuer.key, now)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := key.Open(*task, j.authority, j.scope, c.RecipientID, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secret.Close)
	return task, secret
}

func softwareResult(t *testing.T, j *SoftwareJournal, i *Identity, task enrollment.SoftwareTask, nonce []byte, state string) *enrollment.SoftwareResult {
	t.Helper()
	zero := uint32(0)
	outcome := enrollment.SoftwareOutcome{State: "observed", Execution: "started", ExitCode: &zero, Before: enrollment.SoftwareObservation{State: "absent"}, After: enrollment.SoftwareObservation{State: "present", Version: "1.2.3"}}
	if state == "uncertain" {
		outcome = enrollment.SoftwareOutcome{State: state, Execution: "unknown", Before: enrollment.SoftwareObservation{State: "unknown"}, After: enrollment.SoftwareObservation{State: "unknown"}, Error: "interrupted"}
	}
	hash, err := task.Digest()
	if err != nil {
		t.Fatal(err)
	}
	r, err := enrollment.SignSoftwareResult(task.Context, j.scope, hash, nonce, outcome, j.certificate, i.Keys.Certificate, j.store.renewalTime())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func runDurableSoftwareJournal(t *testing.T, backend NativeBackend) {
	t.Helper()
	s, i, j, task, secret := softwareFixture(t, backend)
	before := make(map[string][]byte)
	for _, name := range []string{pendingRecord, identityRecord, softwareRecord("recipient", 1)} {
		data, err := backend.Load(name)
		if err != nil {
			t.Fatal(err)
		}
		before[name] = data
		defer clear(data)
	}
	if err := j.RecordResult(*softwareResult(t, j, i, *task, secret.Nonce(), "observed")); err == nil {
		t.Fatal("result accepted without intent")
	}
	type admission struct {
		won bool
		err error
	}
	results := make(chan admission, 4)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			other := &Store{backend: backend}
			journal, err := other.OpenSoftwareJournal(i)
			if err != nil {
				results <- admission{err: err}
				return
			}
			won, entry, err := journal.Begin(*task, secret)
			if entry != nil {
				entry.Close()
			}
			results <- admission{won, err}
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.won {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("expected exactly one durable creator", winners)
	}
	// A journal opened before another process's winning publication must refresh
	// its index before admitting anything; the backend, not its mutex, decides.
	won, entry, err := j.Begin(*task, secret)
	if err != nil || won || entry == nil || entry.Result != nil {
		t.Fatal("prior intent authorized replay", err)
	}
	defer entry.Close()
	r := softwareResult(t, j, i, *task, entry.Nonce, "observed")
	for range 2 {
		if err := j.RecordResult(*r); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.RecordResult(*softwareResult(t, j, i, *task, entry.Nonce, "uncertain")); err == nil {
		t.Fatal("conflicting result replaced history")
	}
	restarted, err := s.OpenSoftwareJournal(i)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Lookup(*task)
	if err != nil || got == nil || got.Result == nil {
		t.Fatal("restart lost result", err)
	}
	defer got.Close()
	expected, _ := json.Marshal(r)
	defer clear(expected)
	actual, _ := json.Marshal(got.Result)
	defer clear(actual)
	if !bytes.Equal(actual, expected) {
		t.Fatal("restart changed signed result")
	}
	for name, original := range before {
		data, err := backend.Load(name)
		if err != nil || !bytes.Equal(original, data) {
			t.Fatal("existing protected state changed", name, err)
		}
		clear(data)
	}
	for _, stage := range []string{"start", "result"} {
		data, err := backend.Load(softwareRecord(stage, 1))
		if err != nil || bytes.Contains(data, []byte("private-source")) || bytes.Contains(data, []byte("private-license")) {
			t.Fatal("journal exposed installer plan", err)
		}
		clear(data)
	}
}

func TestSoftwareJournalDurableExclusiveAdmissionAndReceipt(t *testing.T) {
	runDurableSoftwareJournal(t, newMemoryBackend(t))
}

func runSoftwareBootJournal(t *testing.T, backend NativeBackend, legacy bool) {
	t.Helper()
	s, i, j, task, secret := softwareFixture(t, backend)
	boot := windowssoftware.BootSession{Sequence: 41, SystemProcessCreated: 130000000000000001}
	var won bool
	var entry *SoftwareEntry
	var err error
	if legacy {
		won, entry, err = j.Begin(*task, secret)
	} else {
		won, entry, err = j.BeginWithBootSession(*task, secret, boot)
	}
	if err != nil || !won || entry == nil || entry.BootSession.Valid() == legacy {
		t.Fatal("admission boot binding", err)
	}
	entry.Close()
	original, err := backend.Load(softwareRecord("start", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	// A later agent/store instance must retain the admission session. A restored
	// old-format entry must not be upgraded with evidence from the current boot.
	restarted, err := s.OpenSoftwareJournal(i)
	if err != nil {
		t.Fatal(err)
	}
	later := windowssoftware.BootSession{Sequence: 42, SystemProcessCreated: boot.SystemProcessCreated + 1}
	won, entry, err = restarted.BeginWithBootSession(*task, secret, later)
	if err != nil || won || entry == nil || entry.BootSession.Valid() == legacy || !legacy && entry.BootSession != boot {
		t.Fatal("retry replaced admission session", err)
	}
	defer entry.Close()
	retained, err := backend.Load(softwareRecord("start", 1))
	defer clear(retained)
	if err != nil || !bytes.Equal(original, retained) {
		t.Fatal("immutable admission changed", err)
	}
	if err = j.RecordResult(*softwareResult(t, j, i, *task, entry.Nonce, "uncertain")); err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Lookup(*task)
	if err != nil || recovered == nil || recovered.Result == nil || recovered.BootSession != entry.BootSession {
		t.Fatal("receipt lost admission evidence", err)
	}
	recovered.Close()
}

func TestSoftwareJournalKeepsAdmissionBootAndLegacyAbsence(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "legacy"}[legacy], func(t *testing.T) { runSoftwareBootJournal(t, newMemoryBackend(t), legacy) })
	}
}

func TestSoftwareJournalRejectsMalformedBootAndRecoversLostAdmission(t *testing.T) {
	for _, mutation := range []string{"missing", "invalid", "noncanonical", "lost_commit"} {
		t.Run(mutation, func(t *testing.T) {
			b := newMemoryBackend(t)
			s, i, j, task, secret := softwareFixture(t, b)
			boot := windowssoftware.BootSession{Sequence: 41, SystemProcessCreated: 130000000000000001}
			if _, _, err := j.BeginWithBootSession(*task, secret, windowssoftware.BootSession{}); err == nil {
				t.Fatal("absent boot evidence admitted execution")
			}
			if mutation == "lost_commit" {
				b.failCreate, b.commitBeforeError = softwareRecord("start", 1), true
			}
			won, entry, err := j.BeginWithBootSession(*task, secret, boot)
			if mutation == "lost_commit" {
				if err == nil || won || entry != nil {
					t.Fatal("lost commit admitted execution")
				}
				b.failCreate = ""
			} else {
				if err != nil || !won {
					t.Fatal(err)
				}
				entry.Close()
				fields, err := decodeFields(b.records[softwareRecord("start", 1)], softwareStartMagicV2, 5)
				if err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "missing":
					fields = fields[:4]
				case "invalid":
					fields[4] = []byte(`{"sequence":42,"system_process_created":0}`)
				case "noncanonical":
					fields[4] = append([]byte(" "), fields[4]...)
				}
				data, err := encodeFields(softwareStartMagicV2, fields...)
				if err != nil {
					t.Fatal(err)
				}
				b.records[softwareRecord("start", 1)] = data
			}
			j, err = s.OpenSoftwareJournal(i)
			if mutation != "lost_commit" {
				if err == nil {
					t.Fatal("corrupt immutable boot evidence reopened")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			won, entry, err = j.BeginWithBootSession(*task, secret, windowssoftware.BootSession{Sequence: 42, SystemProcessCreated: boot.SystemProcessCreated + 1})
			if err != nil || won || entry == nil || entry.BootSession != boot {
				t.Fatal("crash recovery rewrote admission evidence", err)
			}
			entry.Close()
		})
	}
}

func TestSoftwareJournalLostCommitNeverRetriesAndRecoversExactResult(t *testing.T) {
	for _, stage := range []string{"start", "result"} {
		t.Run(stage, func(t *testing.T) {
			b := newMemoryBackend(t)
			s, i, j, task, secret := softwareFixture(t, b)
			b.failCreate, b.commitBeforeError = softwareRecord(stage, 1), true
			won, entry, err := j.Begin(*task, secret)
			if stage == "start" {
				if won || !errors.Is(err, ErrUnavailable) {
					t.Fatal("unacknowledged intent admitted work", err)
				}
			} else {
				if err != nil || !won {
					t.Fatal(err)
				}
				defer entry.Close()
				if err = j.RecordResult(*softwareResult(t, j, i, *task, entry.Nonce, "observed")); !errors.Is(err, ErrUnavailable) {
					t.Fatal("lost result commit reported success", err)
				}
			}
			b.failCreate = ""
			j, err = s.OpenSoftwareJournal(i)
			if err != nil {
				t.Fatal(err)
			}
			won, entry, err = j.Begin(*task, secret)
			if err != nil || won || entry == nil {
				t.Fatal("crash recovery admitted another installer", err)
			}
			defer entry.Close()
			if (entry.Result != nil) != (stage == "result") {
				t.Fatal("lost commit changed durable outcome")
			}
		})
	}
}

func TestSoftwareJournalRejectsPartialRestoreAndForeignRecords(t *testing.T) {
	for _, mutation := range []string{"missing_start", "gap", "corrupt_result", "foreign_binding", "missing_identity"} {
		t.Run(mutation, func(t *testing.T) {
			b := newMemoryBackend(t)
			s, i, j, task, secret := softwareFixture(t, b)
			_, entry, err := j.Begin(*task, secret)
			if err != nil {
				t.Fatal(err)
			}
			defer entry.Close()
			if err = j.RecordResult(*softwareResult(t, j, i, *task, entry.Nonce, "observed")); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing_start":
				delete(b.records, softwareRecord("start", 1))
			case "gap":
				b.records[softwareRecord("start", 2)] = b.records[softwareRecord("start", 1)]
				delete(b.records, softwareRecord("start", 1))
				delete(b.records, softwareRecord("result", 1))
			case "corrupt_result":
				b.records[softwareRecord("result", 1)] = []byte("corrupt")
			case "foreign_binding":
				b.records[softwareRecord("start", 1)][len(softwareStartMagic)+4] ^= 1
			case "missing_identity":
				delete(b.records, pendingRecord)
				delete(b.records, identityRecord)
				delete(b.records, softwareRecord("recipient", 1))
			}
			if _, err = s.OpenSoftwareJournal(i); !errors.Is(err, ErrUnavailable) {
				t.Fatal("partial/foreign journal accepted", err)
			}
			if mutation == "missing_identity" {
				if _, err = s.Load(); !errors.Is(err, ErrUnavailable) {
					t.Fatal("orphan software history treated as empty enrollment", err)
				}
			}
		})
	}
}

func TestSoftwareRecipientRotatesWithCertificateAndPreservesHistoricalJournal(t *testing.T) {
	b := newMemoryBackend(t)
	f := newRenewalFixture(t, b, "windows")
	old, err := f.store.LoadOrCreateSoftwareRecipient(f.original)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	oldJournal, err := f.store.OpenSoftwareJournal(f.original)
	if err != nil {
		t.Fatal(err)
	}
	task, secret := softwareJournalTask(t, oldJournal, old, f.issuer)
	won, entry, err := oldJournal.Begin(*task, secret)
	if err != nil || !won || entry == nil {
		t.Fatal("old generation admission failed", err)
	}
	defer entry.Close()
	result := softwareResult(t, oldJournal, f.original, *task, entry.Nonce, "observed")
	if err = oldJournal.RecordResult(*result); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	defer clear(encoded)
	prepared, err := f.store.prepareRenewal(t.Context(), f.prepare)
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.store.confirmRenewal(t.Context(), prepared.ID, f.confirm)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	key, err := f.store.LoadOrCreateSoftwareRecipient(current)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	if bytes.Equal(old.PublicKey(), key.PublicKey()) {
		t.Fatal("certificate renewal reused software encryption key")
	}
	if _, err = f.store.LoadOrCreateSoftwareRecipient(f.original); !errors.Is(err, ErrUnavailable) {
		t.Fatal("retired generation registered a key", err)
	}
	if oldJournal.active() {
		t.Fatal("retired journal still authorizes new work")
	}
	for _, n := range []int{1, 2} {
		if _, err = b.Load(softwareRecord("recipient", n)); err != nil {
			t.Fatal("generation record lost", err)
		}
	}
	currentJournal, err := f.store.OpenSoftwareJournal(current)
	if err != nil {
		t.Fatal("new generation could not open permanent journal", err)
	}
	retained, err := currentJournal.Lookup(*task)
	if err != nil || retained == nil || retained.Result == nil {
		t.Fatal("renewal lost historical result", err)
	}
	defer retained.Close()
	actual, _ := json.Marshal(retained.Result)
	defer clear(actual)
	if !bytes.Equal(encoded, actual) {
		t.Fatal("renewal rewrote historical signer/outcome")
	}
	if won, _, err := oldJournal.Begin(*task, secret); won || !errors.Is(err, ErrUnavailable) {
		t.Fatal("retired journal admitted old task", err)
	}
	if won, _, err := currentJournal.Begin(*task, secret); won || !errors.Is(err, ErrUnavailable) {
		t.Fatal("current journal executed old certificate task", err)
	}
	proof, err := enrollment.SignSoftwareSubmission(*retained.Result, currentJournal.scope, currentJournal.certificate, current.Keys.Certificate, f.now)
	if err != nil || enrollment.VerifySoftwareSubmission(*proof, *retained.Result, currentJournal.scope, currentJournal.certificate, f.now) != nil {
		t.Fatal("current generation could not submit exact old result", err)
	}
}
