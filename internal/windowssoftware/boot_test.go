package windowssoftware

import (
	"encoding/binary"
	"testing"
)

func TestBootSessionRequiresLaterSequenceAndDifferentSystemProcess(t *testing.T) {
	original := BootSession{Sequence: 41, SystemProcessCreated: 130000000000000001}
	for _, test := range []struct {
		name    string
		current BootSession
		later   bool
	}{
		{"same_kernel", original, false}, {"service_restart", original, false},
		{"resume_or_sequence_only", BootSession{42, original.SystemProcessCreated}, false},
		{"clock_or_process_only", BootSession{41, original.SystemProcessCreated + 1}, false},
		{"later_kernel", BootSession{42, original.SystemProcessCreated + 1}, true},
		{"clock_moved_back_across_boot", BootSession{42, original.SystemProcessCreated - 1}, true},
		{"restored_counter", BootSession{40, original.SystemProcessCreated + 1}, false},
		{"missing_process", BootSession{42, 0}, false}, {"invalid_process_time", BootSession{42, 1 << 63}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.current.After(original) != test.later {
				t.Fatal("invalid kernel transition evidence")
			}
		})
	}
	if original.After(BootSession{}) || (BootSession{0, original.SystemProcessCreated + 1}).After(BootSession{^uint32(0), original.SystemProcessCreated}) {
		t.Fatal("missing or wrapped evidence became a later boot")
	}
}

func TestSystemProcessCreationRequiresCompleteUnambiguousSnapshot(t *testing.T) {
	fixture := func() []byte {
		data := make([]byte, 3*systemProcessHeaderSize)
		for index, pid := range []uint64{0, 4, 1234} {
			row := data[index*systemProcessHeaderSize:]
			if index < 2 {
				binary.LittleEndian.PutUint32(row, systemProcessHeaderSize)
			}
			binary.LittleEndian.PutUint64(row[systemProcessPIDOffset:], pid)
			binary.LittleEndian.PutUint64(row[systemProcessCreatedOffset:], 130000000000000001+pid)
		}
		return data
	}
	good := fixture()
	if value, err := systemProcessCreation(good); err != nil || value != 130000000000000005 {
		t.Fatal("System process evidence missing", err)
	}
	for _, mutation := range []func([]byte) []byte{
		func(data []byte) []byte { return data[:0] }, func(data []byte) []byte { return data[:len(data)-1] },
		func(data []byte) []byte { binary.LittleEndian.PutUint32(data, 4); return data },
		func(data []byte) []byte { binary.LittleEndian.PutUint32(data, ^uint32(0)); return data },
		func(data []byte) []byte { binary.LittleEndian.PutUint64(data[systemProcessPIDOffset:], 4); return data },
		func(data []byte) []byte {
			binary.LittleEndian.PutUint64(data[systemProcessHeaderSize+systemProcessPIDOffset:], 8)
			return data
		},
		func(data []byte) []byte {
			binary.LittleEndian.PutUint64(data[systemProcessHeaderSize+systemProcessCreatedOffset:], 0)
			return data
		},
		func(data []byte) []byte {
			binary.LittleEndian.PutUint64(data[systemProcessHeaderSize+systemProcessCreatedOffset:], 1<<63)
			return data
		},
	} {
		if _, err := systemProcessCreation(mutation(fixture())); err == nil {
			t.Fatal("malformed snapshot accepted")
		}
	}
}

func FuzzSystemProcessCreation(f *testing.F) {
	f.Add(make([]byte, systemProcessHeaderSize))
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		created, err := systemProcessCreation(data)
		if err == nil && !(BootSession{SystemProcessCreated: created}).Valid() {
			t.Fatal("invalid process evidence")
		}
	})
}
