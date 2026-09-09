//go:build !darwin

package macsecurity

func BootSessionID() (string, error) { return "", ErrRotationUnsupported }
