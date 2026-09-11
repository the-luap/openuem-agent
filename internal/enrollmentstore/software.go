package enrollmentstore

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/windowssoftware"
)

// Permanent history is bounded and never recycled. Exhaustion stops new work;
// it requires a separately authorized migration preserving replay evidence.
const MaxSoftwareAttempts = 4096

const (
	softwareRecipientMagic = "openuem/enrollment/software/recipient/v1\x00"
	softwareBindingMagic   = "openuem/enrollment/software/binding/v1\x00"
	softwareStartMagic     = "openuem/enrollment/software/start/v1\x00"
	softwareStartMagicV2   = "openuem/enrollment/software/start/v2\x00"
	softwareResultMagic    = "openuem/enrollment/software/result/v1\x00"
)

func softwareRecord(stage string, ordinal int) string {
	return fmt.Sprintf("software-%s-v1-%04d", stage, ordinal)
}

func (s *Store) softwareRecordsAbsent() bool {
	if inventory, ok := s.backend.(interface{ hasSoftwareRecords() (bool, error) }); ok {
		present, err := inventory.hasSoftwareRecords()
		return err == nil && !present
	}
	for _, stage := range []string{"recipient", "start", "result"} {
		limit := MaxSoftwareAttempts
		if stage == "recipient" {
			limit = MaxIdentityRenewalAttempts + 1
		}
		for n := 1; n <= limit; n++ {
			data, err := s.backend.Load(softwareRecord(stage, n))
			clear(data)
			if !errors.Is(err, ErrMissing) {
				return false
			}
		}
	}
	return true
}

// softwareBinding revalidates the durable selected generation, not just a
// previously loaded key. Call while holding the Store lifetime lock.
func (s *Store) softwareBinding(expected *Identity) (*Identity, []byte, error) {
	if s.backend == nil || expected == nil || expected.Platform != "windows" || expected.Keys == nil || expected.Keys.Certificate == nil {
		return nil, nil, ErrUnavailable
	}
	p, err := s.loadPending()
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	defer p.close()
	current, err := s.loadIdentity(p)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	if current.Response != expected.Response || current.Origin != expected.Origin || current.Platform != expected.Platform || !current.Keys.Certificate.PublicKey.Equal(&expected.Keys.Certificate.PublicKey) {
		current.Close()
		return nil, nil, ErrUnavailable
	}
	bound, err := json.Marshal(struct {
		Origin, Device string
		Tenant, Site   int
	}{current.Origin, current.Response.DeviceID, current.Response.TenantID, current.Response.SiteID})
	if err != nil {
		current.Close()
		return nil, nil, ErrUnavailable
	}
	binding, err := encodeFields(softwareBindingMagic, p.digest[:], bound)
	if err != nil {
		current.Close()
		return nil, nil, ErrUnavailable
	}
	return current, binding, nil
}

// LoadOrCreateSoftwareRecipient uses a separate X25519 key for each committed
// certificate generation. Old encryption keys never receive new commands, and
// neither the FileVault key nor a signing/broker key is repurposed.
func (s *Store) LoadOrCreateSoftwareRecipient(expected *Identity) (*enrollment.SoftwareRecipientKey, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	current, binding, err := s.softwareBinding(expected)
	if err != nil {
		return nil, err
	}
	defer current.Close()
	ordinal := len(current.certificates)
	if ordinal < 1 || ordinal > MaxIdentityRenewalAttempts+1 {
		return nil, ErrUnavailable
	}
	hash := currentCertificateHash(current)
	if hash == "" {
		return nil, ErrUnavailable
	}
	name := softwareRecord("recipient", ordinal)
	data, err := s.backend.Load(name)
	if errors.Is(err, ErrMissing) {
		key, e := enrollment.NewSoftwareRecipientKey()
		if e != nil {
			return nil, ErrUnavailable
		}
		private, e := key.Bytes()
		key.Close()
		if e != nil {
			return nil, ErrUnavailable
		}
		encoded, e := encodeFields(softwareRecipientMagic, binding, []byte(hash), private)
		clear(private)
		if e != nil {
			return nil, ErrUnavailable
		}
		err = s.backend.Create(name, encoded)
		clear(encoded)
		if err != nil && !errors.Is(err, ErrExists) {
			return nil, ErrUnavailable
		}
		data, err = s.backend.Load(name)
	}
	defer clear(data)
	if err != nil {
		return nil, ErrUnavailable
	}
	fields, err := decodeFields(data, softwareRecipientMagic, 3)
	if err != nil || !bytes.Equal(fields[0], binding) || string(fields[1]) != hash {
		return nil, ErrUnavailable
	}
	key, err := enrollment.ParseSoftwareRecipientKey(fields[2])
	if err != nil {
		return nil, ErrUnavailable
	}
	// A concurrent renewal decision may have retired this generation while the
	// key was published. Keep the record, but do not register it as current.
	selected, _, err := s.softwareBinding(expected)
	if err != nil {
		key.Close()
		return nil, ErrUnavailable
	}
	selected.Close()
	return key, nil
}

// SoftwareJournal owns no private keys. Its Store and installation service
// lease must outlive it. Immutable backend publication also excludes competing
// journal objects/processes; its mutex only protects this object's index.
type SoftwareJournal struct {
	mu                     sync.Mutex
	store                  *Store
	binding                []byte
	scope                  enrollment.SoftwareIdentity
	certificate, authority *x509.Certificate
	certificates           map[string]renewalCertificate
	index                  map[string]int
	next                   int
}

type SoftwareEntry struct {
	Task        enrollment.SoftwareTask
	Nonce       []byte
	Result      *enrollment.SoftwareResult
	BootSession windowssoftware.BootSession
}

func (*SoftwareEntry) String() string               { return "[protected Windows software journal entry]" }
func (e *SoftwareEntry) GoString() string           { return e.String() }
func (*SoftwareEntry) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (e *SoftwareEntry) Close() {
	if e != nil {
		clear(e.Nonce)
		e.Nonce = nil
		if e.Result != nil {
			clear(e.Result.Nonce)
			e.Result = nil
		}
	}
}

func (s *Store) OpenSoftwareJournal(expected *Identity) (*SoftwareJournal, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	current, binding, err := s.softwareBinding(expected)
	if err != nil {
		return nil, err
	}
	defer current.Close()
	cert, err := enrollment.ValidateResponse(current.Response, current.Origin, &current.Keys.Certificate.PublicKey, s.renewalTime())
	if err != nil {
		return nil, ErrUnavailable
	}
	block, rest := pem.Decode([]byte(current.Response.Authority))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrUnavailable
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !root.IsCA {
		return nil, ErrUnavailable
	}
	j := &SoftwareJournal{store: s, binding: binding, scope: enrollment.SoftwareIdentity{AgentID: current.Response.DeviceID, TenantID: current.Response.TenantID, SiteID: current.Response.SiteID, CertificateHash: renewalDigest(cert.Raw)}, certificate: cert, authority: root, certificates: current.certificates}
	if err = j.scan(); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *SoftwareJournal) sameScope(c enrollment.SoftwareContext) bool {
	return c.ValidShape() && c.Identity.AgentID == j.scope.AgentID && c.Identity.TenantID == j.scope.TenantID && c.Identity.SiteID == j.scope.SiteID
}
func (j *SoftwareJournal) active() bool {
	if j.store.backend == nil {
		return false
	}
	p, err := j.store.loadPending()
	if err != nil {
		return false
	}
	defer p.close()
	current, err := j.store.loadIdentity(p)
	if err != nil {
		return false
	}
	defer current.Close()
	return current.Platform == "windows" && current.Response.DeviceID == j.scope.AgentID && current.Response.TenantID == j.scope.TenantID && current.Response.SiteID == j.scope.SiteID && currentCertificateHash(current) == j.scope.CertificateHash
}

func (j *SoftwareJournal) validTask(task enrollment.SoftwareTask) bool {
	if !j.sameScope(task.Context) || enrollment.VerifySoftwareTaskHistory(task, j.authority) != nil {
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
func (j *SoftwareJournal) validResult(result enrollment.SoftwareResult) bool {
	history, ok := j.certificates[result.Identity.CertificateHash]
	if !ok || history.certificate == nil || !j.sameScope(result.Context) {
		return false
	}
	return (history.retiredAt.IsZero() || result.SignedAt <= history.retiredAt.Unix()) && enrollment.VerifySoftwareResult(result, history.certificate, j.store.renewalTime()) == nil
}

func (j *SoftwareJournal) read(ordinal int) (*SoftwareEntry, error) {
	start, startErr := j.store.backend.Load(softwareRecord("start", ordinal))
	defer clear(start)
	result, resultErr := j.store.backend.Load(softwareRecord("result", ordinal))
	defer clear(result)
	if errors.Is(startErr, ErrMissing) && errors.Is(resultErr, ErrMissing) {
		return nil, nil
	}
	if startErr != nil || resultErr != nil && !errors.Is(resultErr, ErrMissing) {
		return nil, ErrUnavailable
	}
	magic, count := softwareStartMagic, 4
	if bytes.HasPrefix(start, []byte(softwareStartMagicV2)) {
		magic, count = softwareStartMagicV2, 5
	}
	fields, err := decodeFields(start, magic, count)
	if err != nil || !bytes.Equal(fields[0], j.binding) || string(fields[1]) != fmt.Sprint(ordinal) || len(fields[3]) != 32 {
		return nil, ErrUnavailable
	}
	task, err := enrollment.DecodeSoftwareTask(fields[2])
	if err != nil || !j.validTask(*task) {
		return nil, ErrUnavailable
	}
	entry := &SoftwareEntry{Task: *task, Nonce: bytes.Clone(fields[3])}
	if count == 5 && (decodeCanonicalJSON(fields[4], &entry.BootSession) != nil || !entry.BootSession.Valid()) {
		entry.Close()
		return nil, ErrUnavailable
	}
	if errors.Is(resultErr, ErrMissing) {
		return entry, nil
	}
	fields, err = decodeFields(result, softwareResultMagic, 3)
	if err != nil || !bytes.Equal(fields[0], j.binding) || string(fields[1]) != fmt.Sprint(ordinal) {
		entry.Close()
		return nil, ErrUnavailable
	}
	var saved enrollment.SoftwareResult
	hash, err := task.Digest()
	if err != nil || decodeCanonicalJSON(fields[2], &saved) != nil || !saved.Context.Equal(task.Context) || saved.TaskHash != hash || !bytes.Equal(saved.Nonce, entry.Nonce) || !j.validResult(saved) {
		entry.Close()
		clear(saved.Nonce)
		return nil, ErrUnavailable
	}
	entry.Result = &saved
	return entry, nil
}

// Inspect every bounded slot, including after the first gap. A partial restore
// containing a result without intent or a later attempt is never an empty log.
func (j *SoftwareJournal) scan() error {
	index := make(map[string]int)
	next := MaxSoftwareAttempts + 1
	ordinals := make([]int, MaxSoftwareAttempts)
	nativeInventory := false
	for n := range ordinals {
		ordinals[n] = n + 1
	}
	if inventory, ok := j.store.backend.(interface{ softwareRecordOrdinals() ([]int, error) }); ok {
		nativeInventory = true
		var err error
		ordinals, err = inventory.softwareRecordOrdinals()
		if err != nil {
			return ErrUnavailable
		}
		next = len(ordinals) + 1
		for i, n := range ordinals {
			if n != i+1 || n > MaxSoftwareAttempts {
				return ErrUnavailable
			}
		}
	}
	for _, n := range ordinals {
		entry, err := j.read(n)
		if err != nil {
			return ErrUnavailable
		}
		if entry == nil {
			if nativeInventory {
				return ErrUnavailable
			}
			if next > n {
				next = n
			}
			continue
		}
		id := entry.Task.Context.TaskID
		entry.Close()
		if n > next || index[id] != 0 {
			return ErrUnavailable
		}
		index[id] = n
	}
	j.index, j.next = index, next
	return nil
}

func (j *SoftwareJournal) Lookup(task enrollment.SoftwareTask) (*SoftwareEntry, error) {
	if j == nil || j.store == nil {
		return nil, ErrUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	if j.store.backend == nil || !j.validTask(task) {
		return nil, ErrUnavailable
	}
	return j.lookup(task)
}
func (j *SoftwareJournal) lookup(task enrollment.SoftwareTask) (*SoftwareEntry, error) {
	n := j.index[task.Context.TaskID]
	if n == 0 {
		return nil, nil
	}
	entry, err := j.read(n)
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

// Begin requires an already authenticated/decrypted secret. Only a successful
// exclusive durable creation admits execution. Any prior intent, failed reload
// or lost commit response prohibits another attempt, including across restarts.
func (j *SoftwareJournal) Begin(task enrollment.SoftwareTask, secret *enrollment.SoftwareSecret) (bool, *SoftwareEntry, error) {
	return j.begin(task, secret, nil)
}

// BeginWithBootSession records the native session before execution admission.
// Old records stay readable and can never acquire evidence from a later boot.
func (j *SoftwareJournal) BeginWithBootSession(task enrollment.SoftwareTask, secret *enrollment.SoftwareSecret, boot windowssoftware.BootSession) (bool, *SoftwareEntry, error) {
	if !boot.Valid() {
		return false, nil, ErrUnavailable
	}
	return j.begin(task, secret, &boot)
}

func (j *SoftwareJournal) begin(task enrollment.SoftwareTask, secret *enrollment.SoftwareSecret, boot *windowssoftware.BootSession) (bool, *SoftwareEntry, error) {
	if j == nil || j.store == nil || secret == nil {
		return false, nil, ErrUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	hash, err := task.Digest()
	if err != nil || hash != secret.TaskHash() || !task.Context.Equal(secret.Context) || !j.active() || enrollment.VerifySoftwareTask(task, j.authority, j.scope, task.Context.RecipientID, j.store.renewalTime()) != nil {
		return false, nil, ErrUnavailable
	}
	nonce := secret.Nonce()
	defer clear(nonce)
	if len(nonce) != 32 {
		return false, nil, ErrUnavailable
	}
	for tries := 0; tries < 2; tries++ {
		entry, err := j.lookup(task)
		if err != nil {
			return false, nil, err
		}
		if entry != nil {
			if !bytes.Equal(entry.Nonce, nonce) {
				entry.Close()
				return false, nil, ErrUnavailable
			}
			return false, entry, nil
		}
		if j.next > MaxSoftwareAttempts {
			return false, nil, ErrUnavailable
		}
		if j.next > 1 {
			prior, err := j.read(j.next - 1)
			if err != nil || prior == nil {
				return false, nil, ErrUnavailable
			}
			blocked := prior.Result == nil || prior.Result.Outcome.State == "uncertain" || prior.Result.Outcome.State == "restart_required"
			prior.Close()
			if blocked {
				return false, nil, ErrUnavailable
			}
		}
		wire, err := json.Marshal(task)
		if err != nil {
			return false, nil, ErrUnavailable
		}
		magic := softwareStartMagic
		fields := [][]byte{j.binding, []byte(fmt.Sprint(j.next)), wire, nonce}
		if boot != nil {
			magic = softwareStartMagicV2
			data, err := json.Marshal(boot)
			if err != nil {
				return false, nil, ErrUnavailable
			}
			fields = append(fields, data)
		}
		record, err := encodeFields(magic, fields...)
		if err != nil {
			return false, nil, ErrUnavailable
		}
		err = j.store.backend.Create(softwareRecord("start", j.next), record)
		clear(record)
		if errors.Is(err, ErrExists) {
			if j.scan() != nil {
				return false, nil, ErrUnavailable
			}
			continue
		}
		if err != nil {
			return false, nil, ErrUnavailable
		}
		j.index[task.Context.TaskID] = j.next
		j.next++
		entry, err = j.lookup(task)
		if err != nil || entry == nil || entry.Result != nil || !j.active() || !task.Context.Valid(j.store.renewalTime()) {
			if entry != nil {
				entry.Close()
			}
			return false, nil, ErrUnavailable
		}
		return true, entry, nil
	}
	return false, nil, ErrUnavailable
}

// RecordResult publishes exact signed evidence before network submission. New
// results require the currently selected signer; historical receipts remain
// readable after renewal and are submitted with a fresh current-key proof.
func (j *SoftwareJournal) RecordResult(result enrollment.SoftwareResult) error {
	if j == nil || j.store == nil {
		return ErrUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store.mu.RLock()
	defer j.store.mu.RUnlock()
	if !j.active() || result.Identity != j.scope || !j.validResult(result) {
		return ErrUnavailable
	}
	n := j.index[result.Context.TaskID]
	if n == 0 {
		return ErrUnavailable
	}
	entry, err := j.read(n)
	if err != nil || entry == nil {
		return ErrUnavailable
	}
	defer entry.Close()
	hash, err := entry.Task.Digest()
	if err != nil || result.TaskHash != hash || !result.Context.Equal(entry.Task.Context) || !bytes.Equal(result.Nonce, entry.Nonce) {
		return ErrUnavailable
	}
	wire, err := json.Marshal(result)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(wire)
	if entry.Result != nil {
		previous, _ := json.Marshal(entry.Result)
		defer clear(previous)
		if bytes.Equal(wire, previous) {
			return nil
		}
		return ErrUnavailable
	}
	record, err := encodeFields(softwareResultMagic, j.binding, []byte(fmt.Sprint(n)), wire)
	if err != nil {
		return ErrUnavailable
	}
	err = j.store.backend.Create(softwareRecord("result", n), record)
	clear(record)
	if err != nil && !errors.Is(err, ErrExists) {
		return ErrUnavailable
	}
	saved, err := j.read(n)
	if err != nil || saved == nil {
		return ErrUnavailable
	}
	defer saved.Close()
	previous, err := json.Marshal(saved.Result)
	defer clear(previous)
	if err != nil || saved.Result == nil || !bytes.Equal(wire, previous) || !j.active() {
		return ErrUnavailable
	}
	return nil
}
