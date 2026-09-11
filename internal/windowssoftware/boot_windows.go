package windowssoftware

import (
	"encoding/binary"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// KUSER_SHARED_DATA is a read-only kernel page in this process. Its documented
// BootId is a loader sequence, not SYSTEM_BOOT_ENVIRONMENT_INFORMATION's BCD ID.
// ReadProcessMemory copies bounded data and reports an inaccessible mapping.
func kernelBootSequence() (uint32, error) {
	var architecture uint16
	switch runtime.GOARCH {
	case "amd64":
		architecture = 9
	case "arm64":
		architecture = 12
	default:
		return 0, ErrBootEvidence
	}
	version := windows.RtlGetVersion()
	if version == nil || version.MajorVersion != 10 || version.MinorVersion != 0 || version.BuildNumber < 17763 {
		return 0, ErrBootEvidence
	}
	var data [0x2c8]byte
	var size uintptr
	if windows.ReadProcessMemory(windows.CurrentProcess(), 0x7ffe0000, &data[0], uintptr(len(data)), &size) != nil || size != uintptr(len(data)) {
		return 0, ErrBootEvidence
	}
	if binary.LittleEndian.Uint32(data[0x260:]) != version.BuildNumber || binary.LittleEndian.Uint16(data[0x26a:]) != architecture || binary.LittleEndian.Uint32(data[0x26c:]) != version.MajorVersion || binary.LittleEndian.Uint32(data[0x270:]) != version.MinorVersion {
		return 0, ErrBootEvidence
	}
	return binary.LittleEndian.Uint32(data[0x2c4:]), nil
}

func readSystemProcessCreation() (uint64, error) {
	var layout windows.SYSTEM_PROCESS_INFORMATION
	if unsafe.Sizeof(layout) != systemProcessHeaderSize || unsafe.Offsetof(layout.UniqueProcessID) != systemProcessPIDOffset || unsafe.Offsetof(layout.CreateTime) != systemProcessCreatedOffset {
		return 0, ErrBootEvidence
	}
	size := uint32(64 << 10)
	for tries := 0; tries < 8; tries++ {
		if size > maxBootProcessSnapshot {
			return 0, ErrBootEvidence
		}
		data := make([]byte, size)
		var needed uint32
		err := windows.NtQuerySystemInformation(windows.SystemProcessInformation, unsafe.Pointer(&data[0]), size, &needed)
		if err == nil {
			defer clear(data)
			if needed == 0 || needed > size {
				return 0, ErrBootEvidence
			}
			return systemProcessCreation(data[:needed])
		}
		clear(data)
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) {
			return 0, ErrBootEvidence
		}
		if needed > size {
			size = needed
		} else {
			size *= 2
		}
	}
	return 0, ErrBootEvidence
}

// ReadBootSession performs read-only native queries. A changed sequence during
// the snapshot, unsupported ABI, or missing System process is never evidence.
func ReadBootSession() (BootSession, error) {
	first, err := kernelBootSequence()
	if err != nil {
		return BootSession{}, ErrBootEvidence
	}
	created, err := readSystemProcessCreation()
	if err != nil {
		return BootSession{}, ErrBootEvidence
	}
	second, err := kernelBootSequence()
	if err != nil || first != second {
		return BootSession{}, ErrBootEvidence
	}
	result := BootSession{Sequence: first, SystemProcessCreated: created}
	if !result.Valid() {
		return BootSession{}, ErrBootEvidence
	}
	return result, nil
}
