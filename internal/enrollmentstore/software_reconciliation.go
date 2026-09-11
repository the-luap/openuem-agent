package enrollmentstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/nats/enrollment"
)

const (
	softwareReconciliationMagic    = "openuem/enrollment/software/reconciliation/v1\x00"
	softwareReconciliationAckMagic = "openuem/enrollment/software/reconciliation/ack/v1\x00"
)

// A read-only observation and its signed authorization are published atomically.
// Unlike installer admission, an interrupted read has no external side effect.
// A separate immutable acknowledgement makes offline receipts enumerable after
// task expiry without rewriting evidence or resending acknowledged history.
type SoftwareReconciliationEntry struct {
	Task         enrollment.SoftwareReconciliationTask
	Result       enrollment.SoftwareReconciliationResult
	Acknowledged bool
}

func (*SoftwareReconciliationEntry) String() string {
	return "[protected Windows software reconciliation entry]"
}
func (e *SoftwareReconciliationEntry) GoString() string           { return e.String() }
func (*SoftwareReconciliationEntry) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (e *SoftwareReconciliationEntry) Close() {
	if e != nil {
		clear(e.Result.OriginalNonce)
		e.Result.OriginalNonce = nil
	}
}

func (j *SoftwareJournal) validReconciliationTask(task enrollment.SoftwareReconciliationTask) bool {
	if !j.sameScope(task.Context.Original) || enrollment.VerifySoftwareReconciliationTaskHistory(task, j.authority) != nil {
		return false
	}
	history, ok := j.certificates[task.Context.Identity.CertificateHash]
	if !ok || history.certificate == nil {
		return false
	}
	c := history.certificate
	created := time.Unix(task.Context.CreatedAt, 0)
	return !created.Before(c.NotBefore) && task.Context.ExpiresAt <= c.NotAfter.Unix() && (history.retiredAt.IsZero() || !created.After(history.retiredAt))
}

// originalForReconciliation reads the permanent installer admission, including
// the exact original envelope, nonce and admission boot. Missing is different
// from damaged history: only an absent entry may produce unavailable evidence.
func (j *SoftwareJournal) originalForReconciliation(task enrollment.SoftwareReconciliationTask) (*SoftwareEntry, error) {
	if !j.validReconciliationTask(task) {
		return nil, ErrUnavailable
	}
	n := j.index[task.Context.Original.TaskID]
	if n == 0 {
		return nil, nil
	}
	entry, err := j.read(n)
	if err != nil || entry == nil {
		return nil, ErrUnavailable
	}
	hash, err := entry.Task.Digest()
	if err != nil || hash != task.Context.OriginalTaskHash || !entry.Task.Context.Equal(task.Context.Original) {
		entry.Close()
		return nil, ErrUnavailable
	}
	return entry, nil
}

func (j *SoftwareJournal) LookupSoftwareOriginal(task enrollment.SoftwareReconciliationTask) (*SoftwareEntry, error) {
	if j == nil || j.store == nil {
		return nil, ErrUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	if !j.active() || j.scan() != nil {
		return nil, ErrUnavailable
	}
	return j.originalForReconciliation(task)
}

func (j *SoftwareJournal) validReconciliationResult(task enrollment.SoftwareReconciliationTask, result enrollment.SoftwareReconciliationResult) bool {
	if !j.validReconciliationTask(task) || !result.Context.Equal(task.Context) {
		return false
	}
	hash, err := task.Digest()
	history, ok := j.certificates[result.Context.Identity.CertificateHash]
	if err != nil || result.TaskHash != hash || !ok || history.certificate == nil || !history.retiredAt.IsZero() && result.SignedAt > history.retiredAt.Unix() || enrollment.VerifySoftwareReconciliationResult(result, history.certificate, j.store.renewalTime()) != nil {
		return false
	}
	original, err := j.originalForReconciliation(task)
	if err != nil {
		return false
	}
	if original == nil {
		return result.Outcome.State == "unavailable"
	}
	defer original.Close()
	nonceHash := sha256.Sum256(original.Nonce)
	if enrollment.VerifySoftwareReconciliationEvidence(task, original.Task, result, j.authority, hex.EncodeToString(nonceHash[:]), j.store.renewalTime()) != nil {
		return false
	}
	return result.Outcome.State == "unavailable" || original.BootSession.Valid() && result.Outcome.Admission == original.BootSession
}

func (j *SoftwareJournal) readReconciliation(n int) (*SoftwareReconciliationEntry, error) {
	data, err := j.store.backend.Load(softwareRecord("reconciliation", n))
	defer clear(data)
	ack, ackErr := j.store.backend.Load(softwareRecord("reconciliation-ack", n))
	defer clear(ack)
	if errors.Is(err, ErrMissing) && errors.Is(ackErr, ErrMissing) {
		return nil, nil
	}
	if err != nil || ackErr != nil && !errors.Is(ackErr, ErrMissing) {
		return nil, ErrUnavailable
	}
	fields, err := decodeFields(data, softwareReconciliationMagic, 4)
	if err != nil || !bytes.Equal(fields[0], j.binding) || string(fields[1]) != fmt.Sprint(n) {
		return nil, ErrUnavailable
	}
	task, err := enrollment.DecodeSoftwareReconciliationTask(fields[2])
	if err != nil {
		return nil, ErrUnavailable
	}
	result, err := enrollment.DecodeSoftwareReconciliationResult(fields[3], j.store.renewalTime())
	if err != nil {
		return nil, ErrUnavailable
	}
	entry := &SoftwareReconciliationEntry{Task: *task, Result: *result}
	if !j.validReconciliationResult(*task, *result) {
		entry.Close()
		return nil, ErrUnavailable
	}
	if errors.Is(ackErr, ErrMissing) {
		return entry, nil
	}
	fields, err = decodeFields(ack, softwareReconciliationAckMagic, 3)
	var receipt enrollment.SoftwareReceipt
	want, wantErr := enrollment.SoftwareReconciliationReceipt(*result, j.store.renewalTime())
	if err != nil || !bytes.Equal(fields[0], j.binding) || string(fields[1]) != fmt.Sprint(n) || decodeCanonicalJSON(fields[2], &receipt) != nil || wantErr != nil || receipt != *want {
		entry.Close()
		return nil, ErrUnavailable
	}
	entry.Acknowledged = true
	return entry, nil
}

func (j *SoftwareJournal) scanReconciliations() error {
	ordinals := make([]int, MaxSoftwareAttempts)
	for n := range ordinals {
		ordinals[n] = n + 1
	}
	nativeInventory := false
	if inventory, ok := j.store.backend.(interface{ softwareReconciliationOrdinals() ([]int, error) }); ok {
		var err error
		ordinals, err = inventory.softwareReconciliationOrdinals()
		if err != nil {
			return ErrUnavailable
		}
		nativeInventory = true
	}
	index := make(map[string]int)
	next := 1
	for _, n := range ordinals {
		if n < 1 || n > MaxSoftwareAttempts || nativeInventory && n != next {
			return ErrUnavailable
		}
		entry, err := j.readReconciliation(n)
		if err != nil {
			return ErrUnavailable
		}
		if entry == nil {
			if nativeInventory {
				return ErrUnavailable
			}
			continue
		}
		id := entry.Task.Context.ID
		entry.Close()
		if n != next || index[id] != 0 {
			return ErrUnavailable
		}
		index[id], next = n, n+1
	}
	j.reconciliations, j.nextReconciliation = index, next
	return nil
}

func (j *SoftwareJournal) LookupSoftwareReconciliation(task enrollment.SoftwareReconciliationTask) (*SoftwareReconciliationEntry, error) {
	if j == nil || j.store == nil {
		return nil, ErrUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	if !j.active() || !j.validReconciliationTask(task) || j.scanReconciliations() != nil {
		return nil, ErrUnavailable
	}
	n := j.reconciliations[task.Context.ID]
	if n == 0 {
		return nil, nil
	}
	entry, err := j.readReconciliation(n)
	if err != nil || entry == nil {
		return nil, ErrUnavailable
	}
	want, err := task.Digest()
	got, gotErr := entry.Task.Digest()
	if err != nil || gotErr != nil || want != got {
		entry.Close()
		return nil, ErrUnavailable
	}
	return entry, nil
}

// NextSoftwareReconciliation returns the oldest unacknowledged signed receipt,
// including expired tasks and certificates from earlier committed generations.
func (j *SoftwareJournal) NextSoftwareReconciliation() (*SoftwareReconciliationEntry, error) {
	if j == nil || j.store == nil {
		return nil, ErrUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	if !j.active() || j.scanReconciliations() != nil {
		return nil, ErrUnavailable
	}
	for n := 1; n < j.nextReconciliation; n++ {
		entry, err := j.readReconciliation(n)
		if err != nil || entry == nil {
			return nil, ErrUnavailable
		}
		if !entry.Acknowledged {
			return entry, nil
		}
		entry.Close()
	}
	return nil, nil
}

// RecordSoftwareReconciliation saves the already signed observation before any
// submission. Its signing time, rather than persistence time, must be inside the
// task deadline. Exact retries recover uncertain durable publication responses.
func (j *SoftwareJournal) RecordSoftwareReconciliation(task enrollment.SoftwareReconciliationTask, result enrollment.SoftwareReconciliationResult) error {
	if j == nil || j.store == nil {
		return ErrUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	if !j.active() || j.scan() != nil || j.scanReconciliations() != nil || task.Context.Identity != j.scope || !j.validReconciliationResult(task, result) {
		return ErrUnavailable
	}
	taskWire, err := json.Marshal(task)
	if err != nil {
		return ErrUnavailable
	}
	wire, err := json.Marshal(result)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(wire)
	for range 2 {
		n := j.reconciliations[task.Context.ID]
		if n == 0 {
			n = j.nextReconciliation
			if n > MaxSoftwareAttempts {
				return ErrUnavailable
			}
			record, err := encodeFields(softwareReconciliationMagic, j.binding, []byte(fmt.Sprint(n)), taskWire, wire)
			if err != nil {
				return ErrUnavailable
			}
			err = j.store.backend.Create(softwareRecord("reconciliation", n), record)
			clear(record)
			if errors.Is(err, ErrExists) {
				if j.scanReconciliations() != nil {
					return ErrUnavailable
				}
				continue
			}
			if err != nil {
				return ErrUnavailable
			}
			j.reconciliations[task.Context.ID], j.nextReconciliation = n, n+1
		}
		saved, err := j.readReconciliation(n)
		if err != nil || saved == nil {
			return ErrUnavailable
		}
		previous, err := json.Marshal(saved.Result)
		saved.Close()
		same := err == nil && bytes.Equal(wire, previous)
		clear(previous)
		if !same || !j.active() {
			return ErrUnavailable
		}
		return nil
	}
	return ErrUnavailable
}

// AcknowledgeSoftwareReconciliation is called only after the authenticated
// private transport returns the exact expected receipt. It is not a release
// override: every future admission revalidates the signed original transcript.
func (j *SoftwareJournal) AcknowledgeSoftwareReconciliation(receipt enrollment.SoftwareReceipt) error {
	if j == nil || j.store == nil {
		return ErrUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	if !receipt.Valid() || !j.active() || j.scanReconciliations() != nil {
		return ErrUnavailable
	}
	n := j.reconciliations[receipt.TaskID]
	if n == 0 {
		return ErrUnavailable
	}
	entry, err := j.readReconciliation(n)
	if err != nil || entry == nil {
		return ErrUnavailable
	}
	defer entry.Close()
	want, err := enrollment.SoftwareReconciliationReceipt(entry.Result, j.store.renewalTime())
	if err != nil || receipt != *want {
		return ErrUnavailable
	}
	if entry.Acknowledged {
		return nil
	}
	wire, err := json.Marshal(receipt)
	if err != nil {
		return ErrUnavailable
	}
	record, err := encodeFields(softwareReconciliationAckMagic, j.binding, []byte(fmt.Sprint(n)), wire)
	if err != nil {
		return ErrUnavailable
	}
	err = j.store.backend.Create(softwareRecord("reconciliation-ack", n), record)
	clear(record)
	if err != nil && !errors.Is(err, ErrExists) {
		return ErrUnavailable
	}
	saved, err := j.readReconciliation(n)
	if err != nil || saved == nil {
		return ErrUnavailable
	}
	defer saved.Close()
	if !saved.Acknowledged || !j.active() {
		return ErrUnavailable
	}
	return nil
}

func (j *SoftwareJournal) softwareReconciled(original enrollment.SoftwareTask) (bool, error) {
	if j.scanReconciliations() != nil {
		return false, ErrUnavailable
	}
	hash, err := original.Digest()
	if err != nil {
		return false, ErrUnavailable
	}
	for n := 1; n < j.nextReconciliation; n++ {
		entry, err := j.readReconciliation(n)
		if err != nil || entry == nil {
			return false, ErrUnavailable
		}
		released := entry.Acknowledged && entry.Task.Context.OriginalTaskHash == hash && entry.Task.Context.Original.Equal(original.Context) && entry.Result.Outcome.AllowsRelease(original.Context.Expectation)
		entry.Close()
		if released {
			return true, nil
		}
	}
	return false, nil
}

// A restored acknowledgement cannot disappear behind a later successful task.
// Every admitted successor must retain the evidence that released its earlier
// uncertain intent. A partial history is never interpreted as a new baseline.
func (j *SoftwareJournal) validateSoftwareSequence() error {
	for n := 1; n < j.next-1; n++ {
		entry, err := j.read(n)
		if err != nil || entry == nil {
			return ErrUnavailable
		}
		blocked := entry.Result == nil || entry.Result.Outcome.State == "uncertain" || entry.Result.Outcome.State == "restart_required"
		if blocked {
			released, err := j.softwareReconciled(entry.Task)
			entry.Close()
			if err != nil || !released {
				return ErrUnavailable
			}
		} else {
			entry.Close()
		}
	}
	return nil
}
