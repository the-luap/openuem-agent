//go:build !windows && (!darwin || !cgo)

package enrollmentstore

// Unsupported builds never write secrets to an unencrypted fallback file.
func OpenNative(directory string) (NativeBackend, error) { return nil, ErrUnsupported }
