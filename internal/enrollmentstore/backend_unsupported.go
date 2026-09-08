//go:build !windows

package enrollmentstore

// OpenNative currently has a Windows implementation. A macOS daemon keychain
// backend is a separate integration step; unsupported builds never write secrets
// to an unencrypted fallback file.
func OpenNative(directory string) (NativeBackend, error) { return nil, ErrUnsupported }
