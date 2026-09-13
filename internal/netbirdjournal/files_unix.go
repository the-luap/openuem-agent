//go:build linux || darwin

package netbirdjournal

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) }

func currentFileInfo(path string) (os.FileInfo, error) { return os.Lstat(path) }

func singleLink(file *os.File) bool {
	var info unix.Stat_t
	return unix.Fstat(int(file.Fd()), &info) == nil && info.Nlink == 1
}

func publishFile(temporary, target string, root *os.File) error {
	if err := os.Link(temporary, target); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	return root.Sync()
}
