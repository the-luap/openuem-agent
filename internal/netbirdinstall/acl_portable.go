//go:build !darwin

package netbirdinstall

func nativeInstallerAvailable() bool { return false }

// Portable owned filesystem fixtures exercise the common verifier. Production
// installation is unavailable on these platforms, independently of this helper.
func trustedNativeACL(string) bool { return true }
