package enrollmentstore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func rotationFixture(t *testing.T, backend NativeBackend) (*Store, *Identity, *RotationJournal, *enrollment.RotationTask, []byte) {
	t.Helper()
	s, i := recipientFixture(t, backend)
	agent, err := s.LoadOrCreateRecipient(i)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	console, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer console.Close()
	j, err := s.OpenRotationJournal(i)
	if err != nil {
		t.Fatal(err)
	}
	c := enrollment.RotationContext{Binding: enrollment.RecoveryContext{Version: 1, Identity: j.scope, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: uuid.NewString(), ExpiresAt: time.Now().Add(time.Minute).Unix()}, Ordinal: 1, EscrowID: uuid.NewString(), ReplyKey: hex.EncodeToString(console.PublicKey())}
	nonce := bytes.Repeat([]byte{9}, 32)
	task, err := enrollment.EncryptRotationTask(enrollment.RecoveryRecipient{Identity: j.scope, ID: c.Binding.RecipientID, PublicKey: agent.PublicKey()}, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s, i, j, task, nonce
}

func TestRotationJournalPreservesAdmissionBootAndDoesNotUpgradeLegacyEvidence(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		backend := newMemoryBackend(t)
		_, identity, j, task, nonce := rotationFixture(t, backend)
		defer identity.Close()
		boot := uuid.NewString()
		var admitted bool
		var entry *RotationEntry
		var err error
		if legacy {
			admitted, entry, err = j.Begin(*task, nonce)
		} else {
			admitted, entry, err = j.BeginWithBootSession(*task, nonce, boot)
		}
		if err != nil || !admitted || entry == nil || (entry.BootSessionID == boot) == legacy {
			t.Fatal("incorrect immutable boot admission", err)
		}
		before, err := backend.Load(rotationRecord(false, task.Context.Ordinal))
		if err != nil {
			t.Fatal(err)
		}
		admitted, entry, err = j.BeginWithBootSession(*task, nonce, uuid.NewString())
		if err != nil || admitted || (entry.BootSessionID == boot) == legacy {
			t.Fatal("retry rewrote original boot evidence", err)
		}
		after, err := backend.Load(rotationRecord(false, task.Context.Ordinal))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("boot evidence was replaced", err)
		}
		if _, _, err = j.BeginWithBootSession(*task, nonce, ""); err == nil {
			t.Fatal("missing boot evidence admitted")
		}
	}
}

func journalResult(t *testing.T, j *RotationJournal, i *Identity, c enrollment.RotationContext, nonce []byte, outcome string) *enrollment.RotationResult {
	t.Helper()
	var key []byte
	if outcome == "rotated" || outcome == "unverified" {
		key = []byte("1111-2222-3333-4444-5555-6666")
	}
	r, err := enrollment.NewRotationResult(c, outcome, nonce, key, j.certificate, i.Keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func runDurableRotationJournal(t *testing.T, backend NativeBackend) {
	t.Helper()
	s, i, j, task, nonce := rotationFixture(t, backend)
	boot := uuid.NewString()
	before := make(map[string][]byte)
	for _, name := range []string{pendingRecord, identityRecord, recipientRecord, rotationAnchorRecord} {
		var err error
		before[name], err = backend.Load(name)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(before[name])
	}
	if entry, err := j.Lookup(task.Context); err != nil || entry != nil {
		t.Fatal("empty journal returned an attempt", err)
	}
	if err := j.RecordResult(*journalResult(t, j, i, task.Context, nonce, "invalid")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("result without a durable intent was accepted", err)
	}
	type admission struct {
		admitted bool
		err      error
	}
	results := make(chan admission, 4)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			// Separate Store and journal values prove that a local Store mutex
			// cannot be responsible for exclusive attempt admission.
			other := &Store{backend: backend}
			journal, err := other.OpenRotationJournal(i)
			if err != nil {
				results <- admission{err: err}
				return
			}
			won, _, err := journal.BeginWithBootSession(*task, nonce, boot)
			results <- admission{won, err}
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.admitted {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("attempt did not have exactly one durable creator", winners)
	}
	if won, entry, err := j.BeginWithBootSession(*task, nonce, boot); err != nil || won || entry == nil || entry.Result != nil || !bytes.Equal(entry.Nonce, nonce) {
		t.Fatal("intent-only retry authorized another execution", won, err)
	}
	result := journalResult(t, j, i, task.Context, nonce, "rotated")
	for range 2 {
		if err := j.RecordResult(*result); err != nil {
			t.Fatal("receipt or idempotent write rejected", err)
		}
	}
	if err := j.RecordResult(*journalResult(t, j, i, task.Context, nonce, "uncertain")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("a conflicting result replaced the returned key", err)
	}
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	restarted, err := s.OpenRotationJournal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	won, entry, err := restarted.BeginWithBootSession(*task, nonce, boot)
	if err != nil || won || entry == nil || entry.Result == nil || entry.BootSessionID != boot {
		t.Fatal("restart lost the receipt or admitted another mutation", err)
	}
	want, _ := json.Marshal(result)
	got, _ := json.Marshal(entry.Result)
	if !bytes.Equal(want, got) {
		t.Fatal("restart changed encrypted receipt bytes")
	}
	if _, err = json.Marshal(entry); err == nil || bytes.Contains([]byte(fmt.Sprintf("%v %#v", entry, entry)), nonce) {
		t.Fatal("journal entry has an accidental public representation")
	}
	for name, original := range before {
		after, err := backend.Load(name)
		if err != nil || !bytes.Equal(original, after) {
			t.Fatal("journal rewrote an existing record", name, err)
		}
		clear(after)
	}
	for _, name := range []string{rotationRecord(false, 1), rotationRecord(true, 1)} {
		data, err := backend.Load(name)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) || bytes.Contains(data, []byte("1111-2222-3333-4444-5555-6666")) {
			t.Fatal("journal persisted plaintext key material")
		}
		clear(data)
	}
}

func TestRotationJournalDurableExclusiveAdmissionAndReceipt(t *testing.T) {
	runDurableRotationJournal(t, newMemoryBackend(t))
}

func TestRotationJournalLostIntentCommitNeverReadmits(t *testing.T) {
	b := newMemoryBackend(t)
	s, i, j, task, nonce := rotationFixture(t, b)
	b.failCreate, b.commitBeforeError = rotationRecord(false, 1), true
	if won, _, err := j.Begin(*task, nonce); won || !errors.Is(err, ErrUnavailable) {
		t.Fatal("lost commit response authorized mutation", won, err)
	}
	b.failCreate = ""
	j, err := s.OpenRotationJournal(i)
	if err != nil {
		t.Fatal(err)
	}
	if won, entry, err := j.Begin(*task, nonce); err != nil || won || entry == nil || entry.Result != nil {
		t.Fatal("restart retried an unacknowledged durable intent", err)
	}
	if err = j.RecordResult(*journalResult(t, j, i, task.Context, nonce, "uncertain")); err != nil {
		t.Fatal(err)
	}
}

func TestRotationJournalLostReceiptCommitRecoversExactCiphertext(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			b := newMemoryBackend(t)
			_, i, j, task, nonce := rotationFixture(t, b)
			if won, _, err := j.Begin(*task, nonce); err != nil || !won {
				t.Fatal(err)
			}
			r := journalResult(t, j, i, task.Context, nonce, "unverified")
			b.failCreate, b.commitBeforeError = rotationRecord(true, 1), committed
			if err := j.RecordResult(*r); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unacknowledged receipt publication succeeded", err)
			}
			b.failCreate = ""
			if err := j.RecordResult(*r); err != nil {
				t.Fatal("receipt persistence retry failed", err)
			}
			entry, err := j.Lookup(task.Context)
			if err != nil || entry == nil || entry.Result == nil {
				t.Fatal(err)
			}
			want, _ := json.Marshal(r)
			got, _ := json.Marshal(entry.Result)
			if !bytes.Equal(want, got) {
				t.Fatal("receipt ciphertext changed on persistence retry")
			}
		})
	}
}

func TestRotationJournalRejectsSlotContextNonceAndReceiptConflicts(t *testing.T) {
	b := newMemoryBackend(t)
	_, i, j, task, nonce := rotationFixture(t, b)
	if won, _, err := j.Begin(*task, nonce); err != nil || !won {
		t.Fatal(err)
	}
	for _, mutate := range []func(*enrollment.RotationTask){
		func(v *enrollment.RotationTask) { v.Context.Binding.TaskID = uuid.NewString() },
		func(v *enrollment.RotationTask) { v.Context.Binding.NativeID = uuid.NewString() },
		func(v *enrollment.RotationTask) { v.Context.Binding.KeyID = uuid.NewString() },
		func(v *enrollment.RotationTask) { v.Context.Binding.Identity.SiteID++ },
		func(v *enrollment.RotationTask) { v.Context.Binding.ExpiresAt++ },
		func(v *enrollment.RotationTask) { v.Context.EscrowID = uuid.NewString() },
		func(v *enrollment.RotationTask) {
			v.Envelope.Ciphertext = bytes.Clone(v.Envelope.Ciphertext)
			v.Envelope.Ciphertext[0] ^= 1
		},
	} {
		changed := *task
		mutate(&changed)
		if won, _, err := j.Begin(changed, nonce); won || !errors.Is(err, ErrUnavailable) {
			t.Fatal("conflicting immutable slot accepted", won, err)
		}
	}
	wrongNonce := bytes.Repeat([]byte{7}, 32)
	if won, _, err := j.Begin(*task, wrongNonce); won || !errors.Is(err, ErrUnavailable) {
		t.Fatal("different nonce admitted", err)
	}
	if err := j.RecordResult(*journalResult(t, j, i, task.Context, wrongNonce, "invalid")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("authentic receipt with wrong nonce accepted", err)
	}
	r := journalResult(t, j, i, task.Context, nonce, "rotated")
	r.NewKey.Ciphertext[0] ^= 1
	if err := j.RecordResult(*r); !errors.Is(err, ErrUnavailable) {
		t.Fatal("forged receipt accepted", err)
	}
}

func TestRotationJournalCorruptionAndPartialRestoreFailClosed(t *testing.T) {
	b := newMemoryBackend(t)
	s, i, j, task, nonce := rotationFixture(t, b)
	if won, _, err := j.Begin(*task, nonce); err != nil || !won {
		t.Fatal(err)
	}
	if err := j.RecordResult(*journalResult(t, j, i, task.Context, nonce, "rotated")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{rotationAnchorRecord, rotationRecord(false, 1), rotationRecord(true, 1)} {
		original := bytes.Clone(b.records[name])
		for _, broken := range [][]byte{[]byte("corrupt"), original[:len(original)-1], append(bytes.Clone(original), 0)} {
			b.records[name] = bytes.Clone(broken)
			if _, err := j.Lookup(task.Context); !errors.Is(err, ErrUnavailable) {
				t.Fatal("corrupt journal record accepted", name, err)
			}
		}
		b.records[name] = original
	}
	anchor := b.records[rotationAnchorRecord]
	delete(b.records, rotationAnchorRecord)
	if _, err := s.OpenRotationJournal(i); !errors.Is(err, ErrUnavailable) {
		t.Fatal("orphan attempts recreated the anchor", err)
	}
	b.records[rotationAnchorRecord] = anchor
	start := b.records[rotationRecord(false, 1)]
	delete(b.records, rotationRecord(false, 1))
	if _, err := j.Lookup(task.Context); !errors.Is(err, ErrUnavailable) {
		t.Fatal("orphan result accepted", err)
	}
	b.records[rotationRecord(false, 1)] = start
	wrong := *i
	wrong.Response.SiteID++
	if _, err := s.OpenRotationJournal(&wrong); !errors.Is(err, ErrUnavailable) {
		t.Fatal("foreign identity opened the journal", err)
	}
	for _, name := range []string{pendingRecord, identityRecord, recipientRecord} {
		delete(b.records, name)
	}
	if _, err := s.Load(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("orphan journal permitted fresh enrollment", err)
	}
}

func TestRotationJournalBoundsExpiryAndClosedStore(t *testing.T) {
	b := newMemoryBackend(t)
	s, i, j, task, nonce := rotationFixture(t, b)
	for _, name := range []string{"rotation-start-v1-000", "rotation-start-v1-129", "rotation-result-v1-999", "rotation-start-v1-1", "rotation-start-v1-0001", "rotation-start-v1-+01", "rotation-result-v1-001/../identity"} {
		if validRecord(name) {
			t.Fatal("unbounded journal record name", name)
		}
	}
	for ordinal := 1; ordinal <= enrollment.MaxRotationAttempts; ordinal++ {
		if !validRecord(rotationRecord(false, ordinal)) || !validRecord(rotationRecord(true, ordinal)) {
			t.Fatal("bounded slot unavailable", ordinal)
		}
	}
	for _, ordinal := range []int{0, enrollment.MaxRotationAttempts + 1} {
		changed := *task
		changed.Context.Ordinal = ordinal
		if won, _, err := j.Begin(changed, nonce); err == nil || won {
			t.Fatal("unbounded attempt admitted")
		}
	}
	if won, _, err := j.Begin(*task, nonce); err != nil || !won {
		t.Fatal(err)
	}
	// Backdate a synthetic committed intent to verify late receipt persistence.
	task.Context.Binding.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	fields, err := decodeFields(b.records[rotationRecord(false, 1)], rotationStartMagic, 4)
	if err != nil {
		t.Fatal(err)
	}
	fields[1], _ = json.Marshal(task.Context)
	b.records[rotationRecord(false, 1)], err = encodeFields(rotationStartMagic, fields...)
	if err != nil {
		t.Fatal(err)
	}
	if won, _, err := j.Begin(*task, nonce); won || !errors.Is(err, ErrUnavailable) {
		t.Fatal("expired mutation admitted", err)
	}
	if err := j.RecordResult(*journalResult(t, j, i, task.Context, nonce, "unverified")); err != nil {
		t.Fatal("late encrypted key was discarded", err)
	}
	if entry, err := j.Lookup(task.Context); err != nil || entry == nil || entry.Result == nil {
		t.Fatal("late receipt unavailable", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Lookup(task.Context); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed journal readable", err)
	}
}
