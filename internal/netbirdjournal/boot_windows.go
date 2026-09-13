package netbirdjournal

import "github.com/open-uem/openuem-agent/internal/windowssoftware"

func ReadBoot() (Boot, error) {
	value, err := windowssoftware.ReadBootSession()
	if err != nil {
		return Boot{}, ErrUnavailable
	}
	b := Boot{Platform: "windows", Windows: value}
	if !b.Valid() {
		return Boot{}, ErrUnavailable
	}
	return b, nil
}
