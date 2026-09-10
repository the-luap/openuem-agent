//go:build !windows && !darwin

package enrollmentstore

func AcquireServiceLease(string) (*ServiceLease, error) { return nil, ErrUnsupported }
func (*ServiceLease) validateNative() error             { return ErrUnsupported }
