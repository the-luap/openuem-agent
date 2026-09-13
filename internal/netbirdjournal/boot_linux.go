package netbirdjournal

import (
	"io"
	"os"
	"strings"
)

func ReadBoot() (Boot, error) {
	file, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return Boot{}, ErrUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 64))
	if err != nil {
		return Boot{}, ErrUnavailable
	}
	b := Boot{Platform: "linux", ID: strings.TrimSpace(string(raw))}
	if !b.Valid() {
		return Boot{}, ErrUnavailable
	}
	return b, nil
}
