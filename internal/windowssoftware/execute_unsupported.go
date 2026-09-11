//go:build !windows

package windowssoftware

func nativeInstallerOperations() installerOperations { return installerOperations{} }
