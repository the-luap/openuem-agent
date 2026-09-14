//go:build linux

package netbirdinstall

import "golang.org/x/sys/unix"

func removalSymlinkOpenFlags() int { return unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC }
