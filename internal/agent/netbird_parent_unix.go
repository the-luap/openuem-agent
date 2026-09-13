//go:build !windows

package agent

import (
	"os"
	"syscall"
)

// The native configuration path selects the installation parent. Public read
// access is acceptable for this metadata parent; untrusted write access is not.
// The child journal itself still requires private access controls.
func checkNetbirdParent(path string) error {
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return errNetbirdRuntime
	}
	f, err := os.Open(path)
	if err != nil {
		return errNetbirdRuntime
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm()&0022 != 0 {
		return errNetbirdRuntime
	}
	owner, ok := after.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 && owner.Uid != uint32(os.Geteuid()) {
		return errNetbirdRuntime
	}
	return nil
}
