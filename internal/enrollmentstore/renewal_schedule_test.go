package enrollmentstore

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
)

func TestRenewalScheduleAuthenticatesCandidateTimingAndSurvivesRestart(t *testing.T) {
	f := newRenewalFixture(t, newMemoryBackend(t), "macos")
	initial, err := f.store.RenewalSchedule()
	if err != nil || initial.Pending != nil || !initial.RetryAfter.IsZero() || !initial.ExpiresAt.Equal(f.original.Response.ExpiresAt) {
		t.Fatal("initial authenticated schedule was unavailable", err)
	}
	_, err = f.store.prepareRenewal(t.Context(), func(context.Context, enrollment.RenewalRequest, enrollment.RenewalSource) (*enrollment.PreparedIdentityRenewal, error) {
		return nil, enrollment.ErrEnrollmentBusy
	})
	if !errors.Is(err, enrollment.ErrEnrollmentBusy) {
		t.Fatal(err)
	}
	candidate, err := f.restarted().RenewalSchedule()
	if err != nil || candidate.Pending == nil || candidate.Pending.Stage != "candidate" || !candidate.Pending.CreatedAt.Equal(f.now.Truncate(time.Second)) || !candidate.Pending.ExpiresAt.IsZero() {
		t.Fatal("candidate scheduling lost its protected creation time", err)
	}
	prepared, err := f.store.PrepareRenewal(t.Context(), f.roots)
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := f.restarted().RenewalSchedule()
	if err != nil || schedule.Pending.Stage != "prepared" || !schedule.Pending.ExpiresAt.Equal(prepared.ExpiresAt) || !schedule.Pending.CreatedAt.Equal(candidate.Pending.CreatedAt) {
		t.Fatal("issuance schedule changed candidate age", err)
	}
}

func TestRenewalScheduleCancellationCooldownUsesDurableReceiptAndCurrentExpiry(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "confirmed"}[confirmed], func(t *testing.T) {
			f := newRenewalFixture(t, newMemoryBackend(t), "macos")
			id := f.uncertainRenewal(t, confirmed)
			pending, err := f.restarted().RenewalSchedule()
			if err != nil || pending.Pending.Stage != "confirming" {
				t.Fatal("quarantine lost public recovery metadata", err)
			}
			if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrRenewalHandoff) {
				t.Fatal("schedule granted old keys during quarantine", err)
			}
			identity, err := f.store.ResolveRenewal(t.Context(), id, f.roots)
			if err != nil {
				t.Fatal(err)
			}
			defer identity.Close()
			schedule, err := f.restarted().RenewalSchedule()
			if err != nil || schedule.Pending != nil || !schedule.ExpiresAt.Equal(identity.Response.ExpiresAt) {
				t.Fatal("schedule did not follow selected generation", err)
			}
			if confirmed {
				if !schedule.RetryAfter.IsZero() {
					t.Fatal("activated certificate retained cancellation cooldown")
				}
			} else {
				want := f.now.Add(min(7*24*time.Hour, max(time.Hour, identity.Response.ExpiresAt.Sub(f.now)/2)))
				if !schedule.RetryAfter.Equal(want) {
					t.Fatal("cancellation cooldown did not use authenticated receipt", schedule.RetryAfter, want)
				}
			}
			f.now = schedule.ExpiresAt.Add(time.Hour)
			if later, err := f.restarted().RenewalSchedule(); err != nil || !reflect.DeepEqual(later, schedule) {
				t.Fatal("restart/expiry reset the durable schedule", err)
			}
			if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("public expiry metadata authorized expired keys", err)
			}
		})
	}
}

func TestRenewalScheduleRejectsIncompleteOrCorruptProtectedState(t *testing.T) {
	if schedule, err := (*Store)(nil).RenewalSchedule(); schedule != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil store yielded a schedule")
	}
	backend := newMemoryBackend(t)
	if schedule, err := (&Store{backend: backend}).RenewalSchedule(); schedule != nil || !errors.Is(err, ErrMissing) {
		t.Fatal("empty installation yielded a schedule")
	}
	f := newRenewalFixture(t, backend, "macos")
	id := f.uncertainRenewal(t, false)
	identity, err := f.store.ResolveRenewal(t.Context(), id, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	identity.Close()
	backend.mu.Lock()
	data := backend.records[renewalRecord("resolved", 1)]
	data[len(data)-1] ^= 1
	backend.mu.Unlock()
	if schedule, err := f.restarted().RenewalSchedule(); schedule != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("corrupt resolution yielded a scheduler deadline", err)
	}
}
