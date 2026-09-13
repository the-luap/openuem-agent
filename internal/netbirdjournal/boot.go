package netbirdjournal

import (
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/netbirdcommand"
)

// Boot uses kernel evidence, never an agent process ID or wall-clock restart
// timestamp. Windows additionally requires both a later loader sequence and a
// different original System process creation time.
type Boot struct {
	Platform string
	ID       string
	Windows  enrollment.SoftwareBootSession
}

func (b Boot) Valid() bool {
	switch b.Platform {
	case "linux", "macos":
		return netbirdcommand.ValidRequestID(b.ID) && b.Windows == (enrollment.SoftwareBootSession{})
	case "windows":
		return b.ID == "" && b.Windows.Valid()
	default:
		return false
	}
}

func (b Boot) After(previous Boot) bool {
	if !b.Valid() || !previous.Valid() || b.Platform != previous.Platform {
		return false
	}
	if b.Platform == "windows" {
		return b.Windows.After(previous.Windows)
	}
	return b.ID != previous.ID
}
