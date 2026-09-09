//go:build darwin

package macsecurity

import (
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// BootSessionID identifies this kernel boot, independently of wall-clock
// corrections and agent process restarts. It reads no account or volume data.
func BootSessionID() (string, error) {
	value, err := unix.Sysctl("kern.bootsessionuuid")
	if err != nil {
		return "", ErrRotationUnavailable
	}
	value = strings.ToLower(value)
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || id.String() != value {
		return "", ErrRotationUnavailable
	}
	return value, nil
}
