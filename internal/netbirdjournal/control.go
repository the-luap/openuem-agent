package netbirdjournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
)

// State inspects this live owner's journal without releasing or changing it.
// Time, connection state and control request nonces do not affect its revision.
func (j *Journal) State(now time.Time) netbirdcommand.State {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.stateLocked(now)
}

func (j *Journal) stateLocked(now time.Time) netbirdcommand.State {
	if !j.available() || !j.clockValid(now) {
		return netbirdcommand.State{Status: "unavailable"}
	}
	s := netbirdcommand.State{Status: "ready", Remaining: MaxAttempts - len(j.entries) - len(j.withdrawals)}
	if s.Remaining == 0 {
		s.Status = "full"
	}
	// Last and count identify all changes relevant to admitting the next command.
	// Earlier entries are immutable once a later attempt exists.
	var last any
	if e := j.last; e != nil {
		last = struct {
			Start   start
			Result  *result
			Release *release
			Active  bool
		}{e.start, e.result, e.release, e.active}
		if e.release == nil && (e.result == nil || e.result.Receipt.Status == "unconfirmed") {
			s.Status = "unconfirmed"
			s.PendingID, s.PendingHash = e.start.RequestID, e.start.CommandHash
			if e.active {
				s.Status = "busy"
			} else {
				s.CanRelease = e.result != nil || j.boot.After(e.start.Boot)
			}
		}
	}
	data, err := json.Marshal(struct {
		Installation string
		Identity     netbirdcommand.Identity
		Boot         Boot
		Count        int
		Withdrawals  int
		Last         any
	}{j.installation, j.identity, j.boot, len(j.entries), len(j.withdrawals), last})
	if err != nil {
		return netbirdcommand.State{Status: "unavailable"}
	}
	digest := sha256.Sum256(data)
	s.Revision = hex.EncodeToString(digest[:])
	return s
}

// Query returns exact retained evidence independently of the original command's
// certificate. Its caller must authenticate a fresh request to the current
// identity; Control does so atomically with access to this journal owner.
func (j *Journal) Query(id, digest string) (*netbirdcommand.Receipt, string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.queryLocked(id, digest)
}

func (j *Journal) queryLocked(id, digest string) (*netbirdcommand.Receipt, string, error) {
	if !j.available() {
		return nil, "", ErrUnavailable
	}
	if !netbirdcommand.ValidRequestID(id) || !netbirdcommand.ValidDigest(digest) {
		return nil, "", ErrConflict
	}
	if w := j.withdrawals[id]; w != nil {
		if w.Receipt.CommandHash != digest {
			return nil, "", ErrConflict
		}
		r := w.Receipt
		return &r, w.WithdrawalID, nil
	}
	e := j.entries[id]
	if e == nil {
		return nil, "", nil
	}
	if e.start.CommandHash != digest {
		return nil, "", ErrConflict
	}
	r := e.receipt()
	var releaseID string
	if e.release != nil {
		releaseID = e.release.ReleaseID
	}
	return &r, releaseID, nil
}

// Control validates the current identity and expiry after acquiring the mutex,
// including queued callbacks. A release and its evidence are one serialized
// operation. The service retains this owner until all handlers have joined.
func (j *Journal) Control(ctx context.Context, data []byte) (netbirdcommand.ControlResponse, error) {
	c, err := netbirdcommand.DecodeControl(data)
	if err != nil {
		return netbirdcommand.ControlResponse{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	if ctx == nil || ctx.Err() != nil || !c.Executable(j.identity, now) {
		return netbirdcommand.ControlResponse{}, netbirdcommand.ErrInvalid
	}
	r, _ := netbirdcommand.ControlResponseFor(c, "ok")
	if !j.available() || !j.clockValid(now) {
		r.Outcome = "unavailable"
		return r, nil
	}
	if c.Kind == "removal-state" || c.Kind == "removal-recovery-state" {
		// Only a configured native observer can advertise installed ownership.
		r.Outcome = "unavailable"
		return r, nil
	}
	if c.Kind == "state" || c.Kind == "registration-state" {
		r.State = j.stateLocked(now)
		return r, nil
	}
	if c.Kind == "release" || c.Kind == "withdraw" {
		if c.Kind == "withdraw" {
			err = j.withdrawLocked(c, now)
		} else {
			err = j.releaseLocked(c.ReferenceID, c.CommandHash, c.RequestID, now)
		}
		if err != nil {
			switch {
			case errors.Is(err, ErrPending), errors.Is(err, ErrFull):
				r.Outcome = "blocked"
			case errors.Is(err, ErrConflict):
				r.Outcome = "conflict"
			default:
				r.Outcome = "unavailable"
			}
			return r, nil
		}
	}
	receipt, releaseID, err := j.queryLocked(c.ReferenceID, c.CommandHash)
	switch {
	case errors.Is(err, ErrConflict):
		r.Outcome = "conflict"
	case err != nil:
		r.Outcome = "unavailable"
	case receipt == nil:
		r.Outcome = "missing"
	case receipt.Status == "withdrawn" && c.Version != netbirdcommand.RecoveryVersion:
		r.Outcome = "conflict"
	case c.Version == netbirdcommand.RecoveryVersion && (receipt.Revision != c.Revision || receipt.Operation != c.Operation):
		r.Outcome = "conflict"
	default:
		r.Receipt, r.ReleaseID = *receipt, releaseID
	}
	return r, nil
}
