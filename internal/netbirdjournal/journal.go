// Package netbirdjournal retains immutable, private NetBird execution metadata.
// It never stores command URLs, profile names, provider tokens or setup keys.
package netbirdjournal

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
)

const MaxAttempts = netbirdcommand.MaxJournalAttempts

var (
	ErrUnavailable = errors.New("NetBird execution journal is unavailable")
	ErrConflict    = errors.New("NetBird execution journal conflicts with the command")
	ErrPending     = errors.New("NetBird has an unresolved execution attempt")
	ErrFull        = errors.New("NetBird execution journal reached its attempt limit")
)

type anchor struct {
	Version                int
	Installation, DeviceID string
	TenantID, SiteID       int64
	Individual             bool
}

type start struct {
	RequestID, DeviceID, Revision, CommandHash, Operation string
	IssuedAt, ExpiresAt, RecordedAt                       time.Time
	Boot                                                  Boot
}

type result struct {
	Receipt    netbirdcommand.Receipt
	RecordedAt time.Time
}
type release struct {
	RequestID, CommandHash, ReleaseID string
	RecordedAt                        time.Time
	Boot                              Boot
}
type entry struct {
	index   int
	start   start
	result  *result
	release *release
	active  bool
}

type Journal struct {
	mu           sync.Mutex
	files        *files
	identity     netbirdcommand.Identity
	installation string
	boot         Boot
	entries      map[string]*entry
	withdrawals  map[string]*withdrawal
	last         *entry
	clock        time.Time
	poisoned     bool
}

// Open owns an exclusive process lease until Close. The parent must be an
// administrator-controlled installation directory. Installation is a digest of
// the caller's stable local identity, independent of renewable certificates.
func Open(directory, installation string, identity netbirdcommand.Identity, boot Boot) (*Journal, error) {
	if !netbirdcommand.ValidDigest(installation) || !identity.Valid() || !boot.Valid() {
		return nil, ErrUnavailable
	}
	f, err := openFiles(directory)
	if err != nil {
		return nil, err
	}
	j := &Journal{files: f, installation: installation, identity: identity, boot: boot, entries: map[string]*entry{}, withdrawals: map[string]*withdrawal{}}
	accepted := false
	defer func() {
		if !accepted {
			j.Close()
		}
	}()
	expected := anchor{Version: 1, Installation: installation, DeviceID: identity.DeviceID, TenantID: identity.TenantID, SiteID: identity.SiteID, Individual: identity.Individual}
	names, err := f.names()
	if err != nil {
		return nil, ErrUnavailable
	}
	if !names["anchor.json"] {
		if len(names) != 0 {
			return nil, ErrUnavailable
		}
		if err = f.create("anchor.json", expected); err != nil {
			return nil, ErrUnavailable
		}
	} else {
		var actual anchor
		if f.read("anchor.json", &actual) != nil || actual != expected {
			return nil, ErrConflict
		}
	}
	for index := 1; index <= MaxAttempts; index++ {
		if names[withdrawalName(index)] {
			w := &withdrawal{}
			if index != len(j.entries)+len(j.withdrawals)+1 || f.read(withdrawalName(index), w) != nil || !w.valid(identity.DeviceID) || netbirdcommand.RequiresIndividualIdentity(w.Receipt.Operation) && !identity.Individual || w.Index != index || j.entries[w.Receipt.RequestID] != nil || j.withdrawals[w.Receipt.RequestID] != nil {
				return nil, ErrUnavailable
			}
			if j.last != nil && j.last.release == nil && (j.last.result == nil || j.last.result.Receipt.Status == "unconfirmed") {
				return nil, ErrUnavailable
			}
			j.withdrawals[w.Receipt.RequestID] = w
			j.advance(w.RecordedAt)
			continue
		}
		name := recordName(index, "start")
		if !names[name] {
			continue
		}
		if index != len(j.entries)+len(j.withdrawals)+1 {
			return nil, ErrUnavailable
		}
		e := &entry{index: index}
		if f.read(name, &e.start) != nil || !e.start.valid(identity.DeviceID) || netbirdcommand.RequiresIndividualIdentity(e.start.Operation) && !identity.Individual || j.entries[e.start.RequestID] != nil || j.withdrawals[e.start.RequestID] != nil {
			return nil, ErrUnavailable
		}
		if j.last != nil && j.last.result == nil && j.last.release == nil || j.last != nil && j.last.result != nil && j.last.result.Receipt.Status == "unconfirmed" && j.last.release == nil {
			return nil, ErrUnavailable
		}
		j.entries[e.start.RequestID] = e
		j.last = e
		j.advance(e.start.RecordedAt)
		if names[recordName(index, "result")] {
			e.result = &result{}
			if f.read(recordName(index, "result"), e.result) != nil || !e.start.matches(e.result.Receipt) || e.result.RecordedAt.IsZero() || e.result.Receipt.Status != "completed" && e.result.Receipt.Status != "unconfirmed" {
				return nil, ErrUnavailable
			}
			if e.result.Receipt.Status == "completed" && !e.result.RecordedAt.Before(e.start.ExpiresAt) {
				return nil, ErrUnavailable
			}
			j.advance(e.result.RecordedAt)
		}
		if names[recordName(index, "release")] {
			e.release = &release{}
			if f.read(recordName(index, "release"), e.release) != nil || !e.validRelease() {
				return nil, ErrUnavailable
			}
			j.advance(e.release.RecordedAt)
		}
	}
	accepted = true
	return j, nil
}

func recordName(index int, kind string) string { return fmt.Sprintf("%04d-%s.json", index, kind) }

func (s start) valid(device string) bool {
	return s.DeviceID == device && netbirdcommand.ValidRequestID(s.RequestID) && netbirdcommand.ValidDigest(s.Revision) && netbirdcommand.ValidDigest(s.CommandHash) &&
		netbirdcommand.OperationLifetime(s.Operation) > 0 && s.Boot.Valid() && !s.RecordedAt.IsZero() &&
		s.IssuedAt.Year() >= 1970 && s.ExpiresAt.After(s.IssuedAt) && s.ExpiresAt.Sub(s.IssuedAt) <= netbirdcommand.OperationLifetime(s.Operation) &&
		s.RecordedAt.Before(s.ExpiresAt) && !s.IssuedAt.After(s.RecordedAt.Add(netbirdcommand.ClockAllowance))
}

func (s start) matches(r netbirdcommand.Receipt) bool {
	return r.Valid() && r.RequestID == s.RequestID && r.DeviceID == s.DeviceID && r.Revision == s.Revision && r.CommandHash == s.CommandHash && r.Operation == s.Operation
}
func (e *entry) receipt() netbirdcommand.Receipt {
	if e.result != nil {
		return e.result.Receipt
	}
	return netbirdcommand.Receipt{Version: netbirdcommand.Version, RequestID: e.start.RequestID, DeviceID: e.start.DeviceID, Revision: e.start.Revision, CommandHash: e.start.CommandHash, Operation: e.start.Operation, Status: "unconfirmed"}
}
func (e *entry) validRelease() bool {
	r := e.release
	return r != nil && r.RequestID == e.start.RequestID && r.CommandHash == e.start.CommandHash && netbirdcommand.ValidRequestID(r.ReleaseID) && !r.RecordedAt.IsZero() && r.Boot.Valid() &&
		(e.result != nil && e.result.Receipt.Status == "unconfirmed" || e.result == nil && r.Boot.After(e.start.Boot))
}
func (j *Journal) advance(at time.Time) {
	if at.After(j.clock) {
		j.clock = at
	}
}
func (j *Journal) available() bool { return j.files != nil && !j.poisoned && j.files.valid() == nil }
func (j *Journal) clockValid(now time.Time) bool {
	return !now.IsZero() && !now.Before(j.clock.Add(-netbirdcommand.ClockAllowance))
}

// Lookup is read-only and can return retained evidence after command expiry.
// It still requires the current local identity and exact original command hash.
func (j *Journal) Lookup(c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.available() {
		return nil, ErrUnavailable
	}
	digest, err := c.Digest()
	if err != nil || c.Identity != j.identity {
		return nil, ErrConflict
	}
	if w := j.withdrawals[c.RequestID]; w != nil {
		if !w.Receipt.Matches(c) {
			return nil, ErrConflict
		}
		r := w.Receipt
		return &r, nil
	}
	e := j.entries[c.RequestID]
	if e == nil {
		return nil, nil
	}
	if digest != e.start.CommandHash {
		return nil, ErrConflict
	}
	r := e.receipt()
	return &r, nil
}

// Begin persists and syncs the attempt before returning admitted=true. An
// existing request never admits execution again, even when its result is absent.
func (j *Journal) Begin(c netbirdcommand.Command, now time.Time) (bool, *netbirdcommand.Receipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.beginLocked(c, now, "")
}

// BeginPrepared atomically binds new installation admission to the journal
// revision under which its private artifact was prepared. Retained exact results
// remain readable; a changed journal can never grant a new installation attempt.
func (j *Journal) BeginPrepared(c netbirdcommand.Command, now time.Time, revision string) (bool, *netbirdcommand.Receipt, error) {
	if c.Version != netbirdcommand.InstallationVersion || !netbirdcommand.ValidDigest(revision) {
		return false, nil, ErrConflict
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.beginLocked(c, now, revision)
}

// BeginRemoval binds native removal admission to the exact journal state used
// by its current native inspection. An old review cannot cross another operation.
func (j *Journal) BeginRemoval(c netbirdcommand.Command, now time.Time, revision string) (bool, *netbirdcommand.Receipt, error) {
	if c.Version != netbirdcommand.RemovalVersion || !netbirdcommand.ValidDigest(revision) {
		return false, nil, ErrConflict
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.beginLocked(c, now, revision)
}

func (j *Journal) beginLocked(c netbirdcommand.Command, now time.Time, revision string) (bool, *netbirdcommand.Receipt, error) {
	if !j.available() || !j.clockValid(now) {
		return false, nil, ErrUnavailable
	}
	digest, err := c.Digest()
	if err != nil || c.Identity != j.identity {
		return false, nil, ErrConflict
	}
	if w := j.withdrawals[c.RequestID]; w != nil {
		if !w.Receipt.Matches(c) {
			return false, nil, ErrConflict
		}
		r := w.Receipt
		return false, &r, nil
	}
	if e := j.entries[c.RequestID]; e != nil {
		if digest != e.start.CommandHash {
			return false, nil, ErrConflict
		}
		r := e.receipt()
		return false, &r, nil
	}
	if (c.Version == netbirdcommand.RemovalVersion || c.Version == netbirdcommand.RemovalRecoveryVersion || c.Version == netbirdcommand.RemovalAbsenceVersion || c.Version == netbirdcommand.RemovalStageCleanupVersion) && revision == "" {
		return false, nil, ErrConflict
	}
	if !c.Executable(j.identity, now) {
		return false, nil, netbirdcommand.ErrInvalid
	}
	if c.Version == netbirdcommand.RemovalRecoveryVersion {
		state, err := j.removalRecoveryStateLocked(c.Identity, c.RemovalRecovery.Original, now)
		if err != nil {
			return false, nil, err
		}
		if c.RemovalRecovery.JournalRevision != state.Revision || revision != state.Revision {
			return false, nil, ErrConflict
		}
	}
	if c.Version == netbirdcommand.RemovalAbsenceVersion {
		state, err := j.removalAbsenceStateLocked(c.Identity, c.RemovalAbsence.Original, now)
		if err != nil {
			return false, nil, err
		}
		if c.RemovalAbsence.JournalRevision != state.Revision || revision != state.Revision {
			return false, nil, ErrConflict
		}
	}
	if c.Version == netbirdcommand.RemovalStageCleanupVersion {
		state, err := j.removalStageCleanupStateLocked(c.Identity, c.RemovalStageCleanup.Original, now)
		if err != nil {
			return false, nil, err
		}
		if c.RemovalStageCleanup.JournalRevision != state.Revision || revision != state.Revision {
			return false, nil, ErrConflict
		}
	}
	if revision != "" {
		state := j.stateLocked(now)
		if state.Status != "ready" || state.Revision != revision {
			return false, nil, ErrConflict
		}
	}
	if j.last != nil && j.last.release == nil && (j.last.result == nil || j.last.result.Receipt.Status == "unconfirmed") {
		return false, nil, ErrPending
	}
	if len(j.entries)+len(j.withdrawals) >= MaxAttempts {
		return false, nil, ErrFull
	}
	e := &entry{index: len(j.entries) + len(j.withdrawals) + 1, start: start{RequestID: c.RequestID, DeviceID: c.DeviceID, Revision: c.Revision, CommandHash: digest, Operation: c.Operation, IssuedAt: c.IssuedAt.UTC(), ExpiresAt: c.ExpiresAt.UTC(), RecordedAt: now.UTC(), Boot: j.boot}, active: true}
	if err = j.files.create(recordName(e.index, "start"), e.start); err != nil {
		j.poisoned = true
		return false, nil, ErrUnavailable
	}
	j.entries[c.RequestID] = e
	j.last = e
	j.advance(now)
	return true, nil, nil
}

// Finish only completes an attempt admitted by this live journal owner. The
// caller must join the owned command before finishing, including on failure.
func (j *Journal) Finish(c netbirdcommand.Command, status string, now time.Time) (*netbirdcommand.Receipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.available() || !j.clockValid(now) {
		return nil, ErrUnavailable
	}
	digest, err := c.Digest()
	if err != nil || c.Identity != j.identity {
		return nil, ErrConflict
	}
	e := j.entries[c.RequestID]
	if e == nil || e.start.CommandHash != digest || e.release != nil || status != "completed" && status != "unconfirmed" {
		return nil, ErrConflict
	}
	if e.result != nil {
		if e.result.Receipt.Status != status {
			return nil, ErrConflict
		}
		r := e.receipt()
		return &r, nil
	}
	if !e.active {
		return nil, ErrPending
	}
	if !now.Before(c.ExpiresAt) {
		status = "unconfirmed"
	}
	receipt, err := netbirdcommand.ReceiptFor(c, status)
	if err != nil {
		return nil, ErrConflict
	}
	value := &result{Receipt: receipt, RecordedAt: now.UTC()}
	if err = j.files.create(recordName(e.index, "result"), value); err != nil {
		j.poisoned = true
		return nil, ErrUnavailable
	}
	e.result = value
	e.active = false
	j.advance(now)
	return &receipt, nil
}

// Release records an explicit authorized acknowledgement. A joined uncertain
// command can be released in this boot. A crash without a result requires a
// demonstrably later kernel boot, so an orphaned command cannot overlap new work.
// Authentication, review and an expiring resolution request belong to the caller.
func (j *Journal) Release(id, digest, releaseID string, now time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.releaseLocked(id, digest, releaseID, now)
}

func (j *Journal) releaseLocked(id, digest, releaseID string, now time.Time) error {
	if !j.available() || !j.clockValid(now) {
		return ErrUnavailable
	}
	if !netbirdcommand.ValidRequestID(releaseID) {
		return ErrConflict
	}
	e := j.entries[id]
	if e == nil || digest != e.start.CommandHash {
		return ErrConflict
	}
	if e.release != nil {
		if e.release.ReleaseID != releaseID {
			return ErrConflict
		}
		return nil
	}
	if e.active || e.result != nil && e.result.Receipt.Status == "completed" || e.result == nil && !j.boot.After(e.start.Boot) {
		return ErrPending
	}
	value := &release{RequestID: id, CommandHash: digest, ReleaseID: releaseID, RecordedAt: now.UTC(), Boot: j.boot}
	if err := j.files.create(recordName(e.index, "release"), value); err != nil {
		j.poisoned = true
		return ErrUnavailable
	}
	e.release = value
	j.advance(now)
	return nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.files == nil {
		return nil
	}
	err := j.files.close()
	j.files = nil
	return err
}

// Retained documents are written in one canonical representation. Requiring it
// on read also rejects duplicate/unknown/null fields and partial records.
func decodeRecord(data []byte, out any) error {
	if json.Unmarshal(data, out) != nil {
		return ErrUnavailable
	}
	canonical, err := json.Marshal(out)
	if err != nil || string(canonical) != string(data) {
		return ErrUnavailable
	}
	return nil
}
