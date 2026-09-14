//go:build darwin && !cgo

package netbirdinstall

func nativeInstallerAvailable() bool { return false }
func trustedNativeACL(string) bool   { return false }
