package netbirdinstall

import "syscall"

func removalChange(stat *syscall.Stat_t) (int64, uint32) {
	return stat.Ctimespec.Sec*1e9 + stat.Ctimespec.Nsec, stat.Flags
}
