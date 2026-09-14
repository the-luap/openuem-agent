package netbirdjournal

import (
	"github.com/open-uem/nats/netbirdcommand"
	"time"
)

// RemovalStageCleanupState associates a new current-state cleanup with an exact
// released unconfirmed uninstall. It never proves an old native descriptor or
// changes the original receipt. Native cleanup needs its own complete acquired owner.
func (j *Journal) RemovalStageCleanupState(identity netbirdcommand.Identity, original netbirdcommand.RemovalStageCleanupReference, now time.Time) (netbirdcommand.State, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.removalStageCleanupStateLocked(identity, original, now)
}

// BeginRemovalStageCleanup requires the independently prepared current review. The
// shared admission checks exact replay before fresh proof and persists a distinct
// minimal attempt before any cleanup Run can record its new observation.
func (j *Journal) BeginRemovalStageCleanup(c netbirdcommand.Command, now time.Time, revision string) (bool, *netbirdcommand.Receipt, error) {
	if c.Version != netbirdcommand.RemovalStageCleanupVersion || !netbirdcommand.ValidDigest(revision) {
		return false, nil, ErrConflict
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.beginLocked(c, now, revision)
}

func (j *Journal) removalStageCleanupStateLocked(identity netbirdcommand.Identity, original netbirdcommand.RemovalStageCleanupReference, now time.Time) (netbirdcommand.State, error) {
	return j.removalAbsenceStateLocked(identity, netbirdcommand.RemovalAbsenceReference{RequestID: original.RequestID, CommandHash: original.CommandHash, Revision: original.Revision, ReleaseID: original.ReleaseID}, now)
}
