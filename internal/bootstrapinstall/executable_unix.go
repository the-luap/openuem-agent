//go:build darwin || linux

package bootstrapinstall

import (
	"os"
	"syscall"
)

func openCodeFile(path string) (*os.File, error) { return os.Open(path) }
func codeFileProtected(_ *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode().Perm()&0022 != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return ErrPackage
	}
	return nil
}
