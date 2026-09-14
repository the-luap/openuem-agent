//go:build darwin

package netbirdinstall

import "golang.org/x/sys/unix"

func removalSymlinkOpenFlags() int {
	// O_SYMLINK opens the link itself. Combining it with O_NOFOLLOW instead
	// rejects that link with ELOOP on macOS; the opened type is checked by fstat.
	return unix.O_RDONLY | unix.O_SYMLINK | unix.O_CLOEXEC
}
