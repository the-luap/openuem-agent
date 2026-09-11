//go:build !windows

package windowssoftware

func ReadBootSession() (BootSession, error) { return BootSession{}, ErrBootEvidence }
