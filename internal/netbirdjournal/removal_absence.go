package netbirdjournal

import (
	"github.com/open-uem/nats/netbirdcommand"
	"time"
)

// RemovalAbsenceState associates a new current-state verification with an exact
// released unconfirmed uninstall. It never proves an old native descriptor or
// changes the original receipt. Native absence needs its own complete observer.
func (j *Journal) RemovalAbsenceState(identity netbirdcommand.Identity, original netbirdcommand.RemovalAbsenceReference, now time.Time) (netbirdcommand.State, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.removalAbsenceStateLocked(identity, original, now)
}

// BeginRemovalAbsence requires the independently prepared current review. The
// shared admission checks exact replay before fresh proof and persists a distinct
// minimal attempt before any verification Run can record its new observation.
func (j *Journal) BeginRemovalAbsence(c netbirdcommand.Command, now time.Time, revision string) (bool, *netbirdcommand.Receipt, error) {
	if c.Version != netbirdcommand.RemovalAbsenceVersion || !netbirdcommand.ValidDigest(revision) {
		return false, nil, ErrConflict
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.beginLocked(c, now, revision)
}
