package enrollmentstore

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/nats/enrollment"
)

const (
	rotationAnchorMagic  = "openuem/enrollment/rotation/anchor/v1\x00"
	rotationStartMagic   = "openuem/enrollment/rotation/start/v1\x00"
	rotationStartMagicV2 = "openuem/enrollment/rotation/start/v2\x00"
	rotationResultMagic  = "openuem/enrollment/rotation/result/v1\x00"
)

// RotationJournal holds no PRK or private signing key. Its Store must remain
// open until all journal users have stopped. The immutable backend, rather than
// a process-local mutex, arbitrates admission across concurrent processes.
type RotationJournal struct {
	store       *Store
	binding     []byte
	scope       enrollment.RecoveryIdentity
	certificate *x509.Certificate
}

type RotationEntry struct {
	BootSessionID string
	Context       enrollment.RotationContext
	Nonce         []byte
	TaskDigest    []byte
	Result        *enrollment.RotationResult
}

func (*RotationEntry) String() string               { return "[protected FileVault rotation journal entry]" }
func (e *RotationEntry) GoString() string           { return e.String() }
func (*RotationEntry) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

func rotationRecord(result bool, ordinal int) string {
	if result {
		return fmt.Sprintf("rotation-result-v1-%03d", ordinal)
	}
	return fmt.Sprintf("rotation-start-v1-%03d", ordinal)
}

// OpenRotationJournal binds an immutable anchor to the already committed local
// installation. Existing enrollment and recipient records are never rewritten.
func (s *Store) OpenRotationJournal(expected *Identity) (*RotationJournal, error) {
	if s == nil || expected == nil || expected.Keys == nil || expected.Keys.Certificate == nil || expected.Platform != "macos" {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backend == nil {
		return nil, ErrUnavailable
	}
	p, err := s.loadPending()
	if err != nil {
		return nil, ErrUnavailable
	}
	defer p.close()
	current, err := s.loadIdentity(p)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer current.Close()
	if current.Response != expected.Response || current.Origin != expected.Origin || current.Platform != expected.Platform || !current.Keys.Certificate.PublicKey.Equal(&expected.Keys.Certificate.PublicKey) {
		return nil, ErrUnavailable
	}
	cert, err := enrollment.ValidateResponse(current.Response, current.Origin, &current.Keys.Certificate.PublicKey, time.Now())
	if err != nil {
		return nil, ErrUnavailable
	}
	hash := sha256.Sum256(cert.Raw)
	scope := enrollment.RecoveryIdentity{AgentID: current.Response.DeviceID, TenantID: current.Response.TenantID, SiteID: current.Response.SiteID, CertificateHash: hex.EncodeToString(hash[:])}
	// The installation anchor excludes certificate DER so a future explicit
	// renewal can retain permanent replay evidence under this same identity.
	bound, _ := json.Marshal(struct {
		Origin   string `json:"origin"`
		DeviceID string `json:"device_id"`
		TenantID int    `json:"tenant_id"`
		SiteID   int    `json:"site_id"`
	}{current.Origin, scope.AgentID, scope.TenantID, scope.SiteID})
	binding, err := encodeFields(rotationAnchorMagic, p.digest[:], bound)
	if err != nil {
		return nil, ErrUnavailable
	}
	anchor, err := s.backend.Load(rotationAnchorRecord)
	if errors.Is(err, ErrMissing) {
		// Missing anchor with surviving attempts is a partial restore, not an
		// empty journal. The fixed attempt bound makes this scan finite.
		for ordinal := 1; ordinal <= enrollment.MaxRotationAttempts; ordinal++ {
			for _, result := range []bool{false, true} {
				data, loadErr := s.backend.Load(rotationRecord(result, ordinal))
				clear(data)
				if !errors.Is(loadErr, ErrMissing) {
					return nil, ErrUnavailable
				}
			}
		}
		err = s.backend.Create(rotationAnchorRecord, binding)
		if err != nil && !errors.Is(err, ErrExists) {
			return nil, ErrUnavailable
		}
		anchor, err = s.backend.Load(rotationAnchorRecord)
	}
	defer clear(anchor)
	if err != nil || !bytes.Equal(anchor, binding) {
		return nil, ErrUnavailable
	}
	return &RotationJournal{store: s, binding: binding, scope: scope, certificate: cert}, nil
}

func (j *RotationJournal) active(c enrollment.RotationContext) bool {
	return j != nil && j.store != nil && j.store.backend != nil && c.ValidReceipt() && c.Binding.Identity == j.scope &&
		time.Now().Before(j.certificate.NotAfter) && !time.Now().Before(j.certificate.NotBefore)
}

func canonicalRotationJSON(data []byte, value any) bool {
	if len(data) == 0 || len(data) > enrollment.MaxRecoveryMessage || json.Unmarshal(data, value) != nil {
		return false
	}
	canonical, err := json.Marshal(value)
	return err == nil && bytes.Equal(data, canonical)
}

// Lookup returns no entry only if both records are absent. An intent without a
// result is evidence of possible execution and must never authorize a retry.
func (j *RotationJournal) Lookup(c enrollment.RotationContext) (*RotationEntry, error) {
	if j == nil || j.store == nil {
		return nil, ErrUnavailable
	}
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	if !j.active(c) {
		return nil, ErrUnavailable
	}
	return j.lookup(c)
}

func (j *RotationJournal) lookup(c enrollment.RotationContext) (*RotationEntry, error) {
	anchor, err := j.store.backend.Load(rotationAnchorRecord)
	defer clear(anchor)
	if err != nil || !bytes.Equal(anchor, j.binding) {
		return nil, ErrUnavailable
	}
	start, startErr := j.store.backend.Load(rotationRecord(false, c.Ordinal))
	defer clear(start)
	result, resultErr := j.store.backend.Load(rotationRecord(true, c.Ordinal))
	defer clear(result)
	if errors.Is(startErr, ErrMissing) && errors.Is(resultErr, ErrMissing) {
		return nil, nil
	}
	if startErr != nil || resultErr != nil && !errors.Is(resultErr, ErrMissing) {
		return nil, ErrUnavailable
	}
	magic, count := rotationStartMagic, 4
	if bytes.HasPrefix(start, []byte(rotationStartMagicV2)) {
		magic, count = rotationStartMagicV2, 5
	}
	fields, err := decodeFields(start, magic, count)
	if err != nil || !bytes.Equal(fields[0], j.binding) || len(fields[2]) != 32 || len(fields[3]) != 32 {
		return nil, ErrUnavailable
	}
	var saved enrollment.RotationContext
	if !canonicalRotationJSON(fields[1], &saved) || saved != c {
		return nil, ErrUnavailable
	}
	entry := &RotationEntry{Context: saved, Nonce: bytes.Clone(fields[2]), TaskDigest: bytes.Clone(fields[3])}
	if count == 5 {
		entry.BootSessionID = string(fields[4])
		if !enrollment.ValidDeviceID(entry.BootSessionID) {
			return nil, ErrUnavailable
		}
	}
	if errors.Is(resultErr, ErrMissing) {
		return entry, nil
	}
	fields, err = decodeFields(result, rotationResultMagic, 2)
	if err != nil || !bytes.Equal(fields[0], j.binding) {
		return nil, ErrUnavailable
	}
	var receipt enrollment.RotationResult
	if !canonicalRotationJSON(fields[1], &receipt) || receipt.Context != c || !bytes.Equal(receipt.Nonce, entry.Nonce) || enrollment.VerifyRotationResult(receipt, j.certificate, time.Now()) != nil {
		return nil, ErrUnavailable
	}
	entry.Result = &receipt
	return entry, nil
}

// Begin returns admitted=true only for the exclusive durable intent creator.
// A lost commit response, conflicting slot or failed reload never admits an OS
// command. The caller must authenticate/decrypt the task before supplying nonce.
func (j *RotationJournal) Begin(task enrollment.RotationTask, nonce []byte) (admitted bool, entry *RotationEntry, err error) {
	return j.begin(task, nonce, "")
}

// BeginWithBootSession preserves kernel boot identity before an OS command can
// start. A different later boot can exclude orphaned commands after agent death.
// Legacy intents remain readable but cannot acquire invented boot evidence.
func (j *RotationJournal) BeginWithBootSession(task enrollment.RotationTask, nonce []byte, boot string) (bool, *RotationEntry, error) {
	if !enrollment.ValidDeviceID(boot) {
		return false, nil, ErrUnavailable
	}
	return j.begin(task, nonce, boot)
}

func (j *RotationJournal) begin(task enrollment.RotationTask, nonce []byte, boot string) (admitted bool, entry *RotationEntry, err error) {
	if j == nil || j.store == nil {
		return false, nil, ErrUnavailable
	}
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	if !j.active(task.Context) || !task.Valid(time.Now()) || len(nonce) != 32 {
		return false, nil, ErrUnavailable
	}
	wire, _ := json.Marshal(task)
	digest := sha256.Sum256(wire)
	entry, err = j.lookup(task.Context)
	if err != nil {
		return false, nil, ErrUnavailable
	}
	if entry == nil {
		bound, _ := json.Marshal(task.Context)
		magic := rotationStartMagic
		fields := [][]byte{j.binding, bound, nonce, digest[:]}
		if boot != "" {
			magic = rotationStartMagicV2
			fields = append(fields, []byte(boot))
		}
		record, err := encodeFields(magic, fields...)
		if err != nil {
			return false, nil, ErrUnavailable
		}
		err = j.store.backend.Create(rotationRecord(false, task.Context.Ordinal), record)
		clear(record)
		admitted = err == nil
		if err != nil && !errors.Is(err, ErrExists) {
			return false, nil, ErrUnavailable
		}
		entry, err = j.lookup(task.Context)
	}
	if err != nil || entry == nil || admitted && entry.BootSessionID != boot || !bytes.Equal(entry.Nonce, nonce) || !bytes.Equal(entry.TaskDigest, digest[:]) || !task.Valid(time.Now()) {
		return false, nil, ErrUnavailable
	}
	if entry.Result != nil {
		admitted = false
	}
	return admitted, entry, nil
}

// RecordResult persists only the authenticated encrypted outcome of an existing
// intent. The complete receipt is immutable and must be durable before sending
// it to the worker. Keep it in memory for persistence retries on transient errors.
func (j *RotationJournal) RecordResult(result enrollment.RotationResult) error {
	if j == nil || j.store == nil {
		return ErrUnavailable
	}
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	if !j.active(result.Context) || enrollment.VerifyRotationResult(result, j.certificate, time.Now()) != nil {
		return ErrUnavailable
	}
	entry, err := j.lookup(result.Context)
	if err != nil || entry == nil || !bytes.Equal(entry.Nonce, result.Nonce) {
		return ErrUnavailable
	}
	wire, _ := json.Marshal(result)
	if entry.Result != nil {
		previous, _ := json.Marshal(entry.Result)
		if bytes.Equal(previous, wire) {
			return nil
		}
		return ErrUnavailable
	}
	record, err := encodeFields(rotationResultMagic, j.binding, wire)
	if err != nil {
		return ErrUnavailable
	}
	err = j.store.backend.Create(rotationRecord(true, result.Context.Ordinal), record)
	clear(record)
	if err != nil && !errors.Is(err, ErrExists) {
		return ErrUnavailable
	}
	entry, err = j.lookup(result.Context)
	if err != nil || entry == nil || entry.Result == nil {
		return ErrUnavailable
	}
	stored, _ := json.Marshal(entry.Result)
	if !bytes.Equal(wire, stored) {
		return ErrUnavailable
	}
	return nil
}
