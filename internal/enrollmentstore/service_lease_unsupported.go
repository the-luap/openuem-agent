//go:build !windows && !darwin && !linux

package enrollmentstore

func AcquireServiceLease(string) (*ServiceLease, error) { return nil, ErrUnsupported }
func (*ServiceLease) validateNative() error             { return ErrUnsupported }
