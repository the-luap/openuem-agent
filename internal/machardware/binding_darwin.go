//go:build darwin

package machardware

import (
	"errors"
	"github.com/open-uem/nats/enrollment"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

// ReadBinding reads only the system's forced preference domain. It never
// consults a user home, defaults search list, environment variable or PATH.
func ReadBinding() (*enrollment.MacBindingProof, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrBinding
	}
	for _, name := range []string{"Library", "Managed Preferences"} {
		next, openErr := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if errors.Is(openErr, unix.ENOENT) {
			return nil, nil
		}
		if openErr != nil {
			return nil, ErrBinding
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || !trustedBindingFile(st, true) {
			unix.Close(fd)
			return nil, ErrBinding
		}
	}
	fileFD, err := unix.Openat(fd, enrollment.MacBindingDomain+".plist", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	unix.Close(fd)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrBinding
	}
	f := os.NewFile(uintptr(fileFD), "managed Mac binding")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fileFD, &st) != nil || !trustedBindingFile(st, false) {
		return nil, ErrBinding
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBindingBytes+1))
	defer clear(data)
	if err != nil {
		return nil, ErrBinding
	}
	return parseBinding(data)
}

func trustedBindingFile(st unix.Stat_t, directory bool) bool {
	want := uint16(unix.S_IFREG)
	if directory {
		want = unix.S_IFDIR
	}
	return st.Uid == 0 && st.Mode&0022 == 0 && st.Mode&unix.S_IFMT == want && (directory || (st.Nlink == 1 && st.Size > 0 && st.Size <= maxBindingBytes))
}
