//go:build !darwin

package macsecurity

func AcquireFileVaultLease(string) (*RotationLease, error) {
	return nil, ErrRotationUnsupported
}
