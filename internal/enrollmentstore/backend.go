// Package enrollmentstore protects the endpoint's individual enrollment state.
// It is separate from legacy shared-certificate configuration.
package enrollmentstore

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/open-uem/nats/enrollment"
)

const (
	maxRecordSize        = 128 << 10
	maxProtectedSize     = maxRecordSize + (64 << 10)
	pendingRecord        = "pending"
	identityRecord       = "identity"
	recipientRecord      = "recipient-v1"
	rotationAnchorRecord = "rotation-anchor-v1"
)

var (
	ErrMissing     = errors.New("individual enrollment state does not exist")
	ErrExists      = errors.New("individual enrollment state already exists")
	ErrUnavailable = errors.New("protected individual enrollment state is unavailable")
	ErrUnsupported = errors.New("native enrollment storage is unavailable on this platform")
)

// NativeBackend stores immutable, separately protected records. Create must
// publish a complete durable record exclusively; it must never replace an existing
// record. Load returns owned plaintext that the caller must clear after decoding.
// These low-level operations do not authorize an origin or perform enrollment.
type NativeBackend interface {
	Load(record string) ([]byte, error)
	Create(record string, plaintext []byte) error
	Close() error
}

func validRecord(record string) bool {
	if record == pendingRecord || record == identityRecord || record == recipientRecord || record == rotationAnchorRecord {
		return true
	}
	for _, prefix := range []string{"rotation-start-v1-", "rotation-result-v1-"} {
		if suffix, ok := strings.CutPrefix(record, prefix); ok {
			n, err := strconv.Atoi(suffix)
			return err == nil && n >= 1 && n <= enrollment.MaxRotationAttempts && suffix == fmt.Sprintf("%03d", n)
		}
	}
	for _, stage := range renewalStages {
		if suffix, ok := strings.CutPrefix(record, "renewal-"+stage+"-v1-"); ok {
			n, err := strconv.Atoi(suffix)
			return err == nil && n >= 1 && n <= MaxIdentityRenewalAttempts && suffix == fmt.Sprintf("%03d", n)
		}
	}
	return false
}
