package enrollmentstore

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/open-uem/nats/enrollment"
)

func restorePendingFixture(t *testing.T) []byte {
	t.Helper()
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseKeys(keys)
	data, err := encodePending(testBootstrap(), keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(data) })
	return data
}

// Exercise only a disposable backend. A retained fragment need not decode:
// missing enrollment anchors cannot authorize replacing any surviving evidence.
func runRetainedSecurityPreventsEnrollment(t *testing.T, backend NativeBackend, record string, pending []byte) {
	t.Helper()
	fragment := []byte("retained isolated security evidence")
	if err := backend.Create(record, fragment); err != nil {
		t.Fatal(err)
	}
	for _, withPending := range []bool{false, true} {
		if withPending {
			if err := backend.Create(pendingRecord, pending); err != nil {
				t.Fatal(err)
			}
		}
		// A new state-machine instance must reach the same decision from durable
		// storage alone, both before and after recovering the original pending keys.
		store := &Store{backend: backend}
		if identity, err := store.Load(); !errors.Is(err, ErrUnavailable) || identity != nil {
			t.Fatal("partial restore became empty or recoverable pending enrollment", withPending, err)
		}
		if !withPending {
			if _, err := store.Checkpoint(); !errors.Is(err, ErrUnavailable) {
				t.Fatal("orphan security history reset the release checkpoint", err)
			}
		}
		called := false
		identity, err := store.enroll(t.Context(), testBootstrap(), func(context.Context, enrollment.Request) (*enrollment.Response, error) {
			called = true
			return nil, enrollment.ErrEnrollmentUnavailable
		})
		if !errors.Is(err, ErrUnavailable) || identity != nil || called {
			t.Fatal("partial restore attempted a network claim", withPending, called, err)
		}
		for _, name := range []string{pendingRecord, identityRecord} {
			data, err := backend.Load(name)
			if withPending && name == pendingRecord {
				if err != nil || !bytes.Equal(data, pending) {
					t.Error("restore changed retained pending keys", err)
				}
			} else if !errors.Is(err, ErrMissing) {
				t.Error("restore published another enrollment record", name, err)
			}
			clear(data)
		}
		data, err := backend.Load(record)
		if err != nil || !bytes.Equal(data, fragment) {
			t.Fatal("partial restore changed retained security evidence", err)
		}
		clear(data)
	}
}

func TestPartialRestoreWithMissingEnrollmentAndJournalAnchorsFailsBeforeClaim(t *testing.T) {
	pending := restorePendingFixture(t)
	records := []string{recipientRecord, rotationAnchorRecord}
	for _, ordinal := range []int{1, enrollment.MaxRotationAttempts / 2, enrollment.MaxRotationAttempts} {
		records = append(records, rotationRecord(false, ordinal), rotationRecord(true, ordinal))
	}
	for _, record := range records {
		t.Run(record, func(t *testing.T) {
			runRetainedSecurityPreventsEnrollment(t, newMemoryBackend(t), record, pending)
		})
	}
}

type failedRestoreRead struct{ NativeBackend }

func (b failedRestoreRead) Load(record string) ([]byte, error) {
	if record == rotationRecord(true, enrollment.MaxRotationAttempts) {
		return nil, ErrUnavailable
	}
	return b.NativeBackend.Load(record)
}

func TestPartialRestoreUnreadableLaterHistoryCannotAuthorizeEnrollment(t *testing.T) {
	b := newMemoryBackend(t)
	pending := restorePendingFixture(t)
	for _, withPending := range []bool{false, true} {
		if withPending {
			if err := b.Create(pendingRecord, pending); err != nil {
				t.Fatal(err)
			}
		}
		store := &Store{backend: failedRestoreRead{b}}
		called := false
		identity, err := store.enroll(t.Context(), testBootstrap(), func(context.Context, enrollment.Request) (*enrollment.Response, error) {
			called = true
			return nil, enrollment.ErrEnrollmentUnavailable
		})
		if !errors.Is(err, ErrUnavailable) || identity != nil || called {
			t.Fatal("unreadable journal history was treated as absent", withPending, called, err)
		}
	}
}
