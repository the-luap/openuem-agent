package windowssoftware

import (
	"encoding/binary"
	"errors"

	"github.com/open-uem/nats/enrollment"
)

var ErrBootEvidence = errors.New("Windows kernel boot evidence is unavailable")

// BootSession joins the loader's boot sequence with the original System process
// creation value. A service restart, clock correction, or resumed System process
// cannot establish a later kernel session. It is not a wall-clock deadline.
type BootSession = enrollment.SoftwareBootSession

const (
	systemProcessHeaderSize    = 256
	systemProcessPIDOffset     = 80
	systemProcessCreatedOffset = 32
	maxBootProcessSnapshot     = 4 << 20
)

// Only PID 4 is retained. Every link is bounds checked before accepting evidence;
// an incomplete, ambiguous or changed-layout process snapshot fails closed.
func systemProcessCreation(data []byte) (uint64, error) {
	if len(data) < systemProcessHeaderSize || len(data) > maxBootProcessSnapshot {
		return 0, ErrBootEvidence
	}
	var created uint64
	for offset := 0; ; {
		if len(data)-offset < systemProcessHeaderSize {
			return 0, ErrBootEvidence
		}
		row := data[offset:]
		next := int(binary.LittleEndian.Uint32(row))
		if next != 0 && (next < systemProcessHeaderSize || next%8 != 0 || next > len(row)-systemProcessHeaderSize) {
			return 0, ErrBootEvidence
		}
		if binary.LittleEndian.Uint64(row[systemProcessPIDOffset:]) == 4 {
			value := binary.LittleEndian.Uint64(row[systemProcessCreatedOffset:])
			if created != 0 || !(BootSession{SystemProcessCreated: value}).Valid() {
				return 0, ErrBootEvidence
			}
			created = value
		}
		if next == 0 {
			break
		}
		offset += next
	}
	if created == 0 {
		return 0, ErrBootEvidence
	}
	return created, nil
}
