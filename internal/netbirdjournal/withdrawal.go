package netbirdjournal

import (
	"time"

	"github.com/open-uem/nats/netbirdcommand"
)

// A withdrawal is a permanent denial of future admission, not an execution
// attempt or a reconstructed result. It contains no original command secrets.
type withdrawal struct {
	Index        int
	Receipt      netbirdcommand.Receipt
	WithdrawalID string
	RecordedAt   time.Time
	Boot         Boot
}

func withdrawalName(index int) string { return recordName(index, "withdrawal") }
func (w *withdrawal) valid(device string) bool {
	return w != nil && w.Index > 0 && w.Index <= MaxAttempts && w.Receipt.Valid() && w.Receipt.Status == "withdrawn" && w.Receipt.DeviceID == device && netbirdcommand.ValidRequestID(w.WithdrawalID) && w.RecordedAt.Year() >= 1970 && w.RecordedAt.Year() <= 9999 && w.Boot.Valid()
}
func (w *withdrawal) matches(c netbirdcommand.ControlRequest) bool {
	r := w.Receipt
	return r.RequestID == c.ReferenceID && r.DeviceID == c.DeviceID && r.Revision == c.Revision && r.CommandHash == c.CommandHash && r.Operation == c.Operation && w.WithdrawalID == c.RequestID
}

func (j *Journal) withdrawLocked(c netbirdcommand.ControlRequest, now time.Time) error {
	if !j.available() || !j.clockValid(now) {
		return ErrUnavailable
	}
	if c.Version != netbirdcommand.RecoveryVersion || c.Kind != "withdraw" || !c.Executable(j.identity, now) {
		return ErrConflict
	}
	if j.entries[c.ReferenceID] != nil {
		return ErrConflict
	}
	if w := j.withdrawals[c.ReferenceID]; w != nil {
		if !w.matches(c) {
			return ErrConflict
		}
		return nil
	}
	if j.last != nil && j.last.release == nil && (j.last.result == nil || j.last.result.Receipt.Status == "unconfirmed") {
		return ErrPending
	}
	if len(j.entries)+len(j.withdrawals) >= MaxAttempts {
		return ErrFull
	}
	w := &withdrawal{Index: len(j.entries) + len(j.withdrawals) + 1, Receipt: netbirdcommand.Receipt{Version: netbirdcommand.Version, RequestID: c.ReferenceID, DeviceID: c.DeviceID, Revision: c.Revision, CommandHash: c.CommandHash, Operation: c.Operation, Status: "withdrawn"}, WithdrawalID: c.RequestID, RecordedAt: now.UTC(), Boot: j.boot}
	if err := j.files.create(withdrawalName(w.Index), w); err != nil {
		j.poisoned = true
		return ErrUnavailable
	}
	j.withdrawals[c.ReferenceID] = w
	j.advance(now)
	return nil
}
