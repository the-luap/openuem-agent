package netbirdjournal

import (
	"errors"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
)

var ErrMissing = errors.New("NetBird original removal attempt is missing")

// RemovalRecoveryState proves the original immutable attempt and its explicit
// release under the current identity. Native inspection separately proves that
// the supplied descriptor belongs to the protected original-UUID manifest.
// Neither proof releases a barrier or changes the original outcome.
func (j *Journal) RemovalRecoveryState(identity netbirdcommand.Identity, original netbirdcommand.RemovalRecoveryReference, now time.Time) (netbirdcommand.State, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.removalRecoveryStateLocked(identity, original, now)
}

func (j *Journal) removalRecoveryStateLocked(identity netbirdcommand.Identity, original netbirdcommand.RemovalRecoveryReference, now time.Time) (netbirdcommand.State, error) {
	if !j.available() || !j.clockValid(now) {
		return netbirdcommand.State{}, ErrUnavailable
	}
	if identity != j.identity || !identity.Valid() || !identity.Individual || !original.Valid() {
		return netbirdcommand.State{}, ErrConflict
	}
	if j.withdrawals[original.RequestID] != nil {
		return netbirdcommand.State{}, ErrConflict
	}
	e := j.entries[original.RequestID]
	if e == nil {
		return netbirdcommand.State{}, ErrMissing
	}
	r := e.receipt()
	if r.DeviceID != identity.DeviceID || r.Operation != "uninstall" || r.CommandHash != original.CommandHash || r.Revision != original.Revision || r.Status != "unconfirmed" {
		return netbirdcommand.State{}, ErrConflict
	}
	if e.active || e.release == nil {
		return netbirdcommand.State{}, ErrPending
	}
	if !e.validRelease() || e.release.ReleaseID != original.ReleaseID {
		return netbirdcommand.State{}, ErrConflict
	}
	s := j.stateLocked(now)
	switch s.Status {
	case "ready":
		return s, nil
	case "full":
		return netbirdcommand.State{}, ErrFull
	case "busy", "unconfirmed":
		return netbirdcommand.State{}, ErrPending
	default:
		return netbirdcommand.State{}, ErrUnavailable
	}
}

// BeginRemovalRecovery admits only a separate new attempt whose current native
// owner was prepared against the inspected journal revision. Exact replays are
// handled first by beginLocked, even after expiry or subsequent journal changes.
func (j *Journal) BeginRemovalRecovery(c netbirdcommand.Command, now time.Time, revision string) (bool, *netbirdcommand.Receipt, error) {
	if c.Version != netbirdcommand.RemovalRecoveryVersion || !netbirdcommand.ValidDigest(revision) {
		return false, nil, ErrConflict
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.beginLocked(c, now, revision)
}
