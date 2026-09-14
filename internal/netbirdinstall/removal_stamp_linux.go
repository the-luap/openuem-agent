package netbirdinstall

import (
	"os"
	"syscall"
)

func removalChange(stat *syscall.Stat_t) (int64, uint32) {
	return int64(stat.Ctim.Sec)*1e9 + int64(stat.Ctim.Nsec), 0
}

// Owned portable fixtures only; production removal remains Darwin-only.
func removalACL(*os.File) (string, bool) { return "", true }
