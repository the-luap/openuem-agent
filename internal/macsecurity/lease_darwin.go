//go:build darwin

package macsecurity

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const rotationLeaseName = ".filevault-rotation.lock"

// AcquireFileVaultLease opens only a fixed empty lock file beneath the already
// provisioned private enrollment directory. Its ancestors must be controlled by
// the installer/root. This function never creates directories or repairs access
// controls. The caller must hold the lease through journal recovery and receipt
// persistence, not just around the OS command.
func AcquireFileVaultLease(directory string) (*RotationLease, error) {
	if os.Geteuid() != 0 {
		return nil, ErrRotationUnsupported
	}
	return acquireFileVaultLease(directory, 0)
}

func acquireFileVaultLease(directory string, owner uint32) (*RotationLease, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrRotationUnavailable
	}
	dirFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRotationUnavailable
	}
	defer unix.Close(dirFD)
	var dirStat unix.Stat_t
	if unix.Fstat(dirFD, &dirStat) != nil || dirStat.Mode&unix.S_IFMT != unix.S_IFDIR || dirStat.Uid != owner || dirStat.Mode&0077 != 0 {
		return nil, ErrRotationUnavailable
	}
	fd, err := unix.Openat(dirFD, rotationLeaseName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrRotationUnavailable
	}
	file := os.NewFile(uintptr(fd), rotationLeaseName)
	accepted := false
	defer func() {
		if !accepted {
			file.Close()
		}
	}()
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != owner || info.Mode&0777 != 0600 || info.Nlink != 1 || info.Size != 0 {
		return nil, ErrRotationUnavailable
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrRotationBusy
		}
		return nil, ErrRotationUnavailable
	}
	// Confirm that the pinned directory/file still name the locked objects.
	// No caller may unlink the persistent file when releasing its lease.
	var currentDir, currentFile unix.Stat_t
	if unix.Lstat(directory, &currentDir) != nil || currentDir.Dev != dirStat.Dev || currentDir.Ino != dirStat.Ino || currentDir.Mode&unix.S_IFMT != unix.S_IFDIR ||
		unix.Fstatat(dirFD, rotationLeaseName, &currentFile, unix.AT_SYMLINK_NOFOLLOW) != nil || currentFile.Dev != info.Dev || currentFile.Ino != info.Ino || currentFile.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, ErrRotationUnavailable
	}
	accepted = true
	return &RotationLease{file: file}, nil
}
