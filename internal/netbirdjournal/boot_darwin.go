package netbirdjournal

import "github.com/open-uem/openuem-agent/internal/macsecurity"

func ReadBoot() (Boot, error) {
	id, err := macsecurity.BootSessionID()
	if err != nil {
		return Boot{}, ErrUnavailable
	}
	b := Boot{Platform: "macos", ID: id}
	if !b.Valid() {
		return Boot{}, ErrUnavailable
	}
	return b, nil
}
