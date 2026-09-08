//go:build darwin

package machardware

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestManagedProofRequiresProtectedRegularSystemFile(t *testing.T) {
	file := unix.Stat_t{Uid: 0, Mode: unix.S_IFREG | 0644, Nlink: 1, Size: 100}
	directory := unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 0755}
	if !trustedBindingFile(file, false) || !trustedBindingFile(directory, true) {
		t.Fatal("protected system path rejected")
	}
	for _, mutate := range []func(*unix.Stat_t){
		func(s *unix.Stat_t) { s.Uid = 501 }, func(s *unix.Stat_t) { s.Mode |= 0020 }, func(s *unix.Stat_t) { s.Mode |= 0002 },
		func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0644 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFIFO | 0644 }, func(s *unix.Stat_t) { s.Nlink = 2 },
		func(s *unix.Stat_t) { s.Size = maxBindingBytes + 1 }, func(s *unix.Stat_t) { s.Size = 0 },
	} {
		copy := file
		mutate(&copy)
		if trustedBindingFile(copy, false) {
			t.Fatal("unsafe managed preference file accepted")
		}
	}
	directory.Mode |= 0020
	if trustedBindingFile(directory, true) {
		t.Fatal("writable parent directory accepted")
	}
}
