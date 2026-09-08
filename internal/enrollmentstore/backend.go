// Package enrollmentstore protects the endpoint's individual enrollment state.
// It is separate from legacy shared-certificate configuration.
package enrollmentstore

import "errors"

const (
	maxRecordSize    = 128 << 10
	maxProtectedSize = maxRecordSize + (64 << 10)
	pendingRecord    = "pending"
	identityRecord   = "identity"
)

var (
	ErrMissing     = errors.New("individual enrollment state does not exist")
	ErrExists      = errors.New("individual enrollment state already exists")
	ErrUnavailable = errors.New("protected individual enrollment state is unavailable")
	ErrUnsupported = errors.New("native enrollment storage is unavailable on this platform")
)

// NativeBackend stores two immutable, separately protected records. Create must
// publish a complete durable record exclusively; it must never replace an existing
// record. Load returns owned plaintext that the caller must clear after decoding.
// These low-level operations do not authorize an origin or perform enrollment.
type NativeBackend interface {
	Load(record string) ([]byte, error)
	Create(record string, plaintext []byte) error
	Close() error
}

func validRecord(record string) bool { return record == pendingRecord || record == identityRecord }
