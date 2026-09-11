package burnbundle

import (
	"bytes"
	"compress/flate"
	"context"
	"io"
	"testing"
)

// cabinetFixture builds owned uncompressed/MSZIP cabinets, including block
// history across 32 KiB boundaries. It contains only caller-provided test bytes.
func cabinetFixture(t testing.TB, payload []byte, compressed, reserve bool) []byte {
	t.Helper()
	data := make([]byte, 36)
	copy(data, "MSCF")
	data[24], data[25] = 3, 1
	put16(data, 26, 1)
	put16(data, 28, 2)
	folderReserve, blockReserve := 0, 0
	if reserve {
		put16(data, 30, 4)
		data = append(data, 3, 0, 2, 1, 0, 0, 0)
		folderReserve, blockReserve = 2, 1
	}
	folder := len(data)
	data = append(data, make([]byte, 8+folderReserve)...)
	if compressed {
		put16(data, folder+6, 1)
	}
	put32(data, 16, uint32(len(data)))
	for i, name := range []string{"0", "a0"} {
		entry := len(data)
		data = append(data, make([]byte, 16)...)
		if i == 0 {
			put32(data, entry, uint32(len(payload)))
		} else {
			put32(data, entry, 4)
			put32(data, entry+4, uint32(len(payload)))
		}
		put16(data, entry+14, 0x20)
		data = append(append(data, []byte(name)...), 0)
	}
	put32(data, folder, uint32(len(data)))
	plain := append(append([]byte(nil), payload...), []byte("tail")...)
	blocks := 0
	for start := 0; start < len(plain); {
		end := min(start+32768, len(plain))
		chunk := plain[start:end]
		encoded := chunk
		if compressed {
			var buffer bytes.Buffer
			buffer.WriteString("CK")
			writer, err := flate.NewWriterDict(&buffer, flate.BestCompression, plain[max(0, start-32768):start])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(chunk); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			encoded = buffer.Bytes()
		}
		block := len(data)
		data = append(data, make([]byte, 8+blockReserve)...)
		put16(data, block+4, uint16(len(encoded)))
		put16(data, block+6, uint16(len(chunk)))
		data = append(data, encoded...)
		blocks++
		start = end
	}
	put16(data, folder+4, uint16(blocks))
	put32(data, 8, uint32(len(data)))
	return data
}

func TestCabinetDirectoryAndExpandedBounds(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		for _, reserve := range []bool{false, true} {
			for _, length := range []int{1, 32768, 70000, int(maxManifestSize)} {
				data := cabinetFixture(t, bytes.Repeat([]byte("x"), length), compressed, reserve)
				index, err := indexCabinet(t.Context(), bytes.NewReader(data), int64(len(data)))
				if err != nil || index.manifestSize != int64(length) || index.files != 2 {
					t.Fatalf("compression=%v reserve=%v length=%d: %+v %v", compressed, reserve, length, index, err)
				}
			}
		}
	}
}

func TestCabinetRejectsAmbiguousAndMalformedMetadata(t *testing.T) {
	changes := map[string]func([]byte){
		"signature":                    func(b []byte) { b[0] = 0 },
		"size":                         func(b []byte) { put32(b, 8, 1) },
		"reserved header":              func(b []byte) { b[4] = 1 },
		"version":                      func(b []byte) { b[24] = 4 },
		"no folders":                   func(b []byte) { put16(b, 26, 0) },
		"too many folders":             func(b []byte) { put16(b, 26, 65) },
		"no files":                     func(b []byte) { put16(b, 28, 0) },
		"too many files":               func(b []byte) { put16(b, 28, 4097) },
		"previous cabinet":             func(b []byte) { put16(b, 30, 1) },
		"next cabinet":                 func(b []byte) { put16(b, 30, 2) },
		"unknown flags":                func(b []byte) { put16(b, 30, 8) },
		"cabinet sequence":             func(b []byte) { put16(b, 34, 1) },
		"directory overlaps folders":   func(b []byte) { put32(b, 16, 36) },
		"directory overflow":           func(b []byte) { put32(b, 16, 0xffffffff) },
		"folder inside directory":      func(b []byte) { put32(b, 36, 44) },
		"folder beyond EOF":            func(b []byte) { put32(b, 36, 0xffffffff) },
		"no blocks":                    func(b []byte) { put16(b, 40, 0) },
		"short block table":            func(b []byte) { put16(b, 40, 65535) },
		"Quantum":                      func(b []byte) { put16(b, 42, 2) },
		"LZX small window":             func(b []byte) { put16(b, 42, 0xe03) },
		"LZX large window":             func(b []byte) { put16(b, 42, 0x1603) },
		"LZX unknown bits":             func(b []byte) { put16(b, 42, 0x9013) },
		"wrong first member":           func(b []byte) { b[60] = 'a' },
		"empty member name":            func(b []byte) { b[60] = 0 },
		"path member":                  func(b []byte) { b[78] = '/' },
		"duplicate member":             func(b []byte) { b[78] = '0'; b[79] = 0 },
		"member execution flag":        func(b []byte) { put16(b, 58, 0x40) },
		"split file":                   func(b []byte) { put16(b, 52, 0xffff) },
		"wrong manifest folder offset": func(b []byte) { put32(b, 48, 1) },
		"empty manifest":               func(b []byte) { put32(b, 44, 0) },
		"oversized manifest":           func(b []byte) { put32(b, 44, uint32(maxManifestSize+1)) },
		"manifest beyond folder":       func(b []byte) { put32(b, 44, 65535) },
		"overlapping member":           func(b []byte) { put32(b, 66, 0) },
		"member beyond folder":         func(b []byte) { put32(b, 62, 65535) },
		"empty data":                   func(b []byte) { put16(b, 85, 0) },
		"split data":                   func(b []byte) { put16(b, 87, 0) },
		"oversized expansion block":    func(b []byte) { put16(b, 87, 32769) },
		"short compressed data":        func(b []byte) { put16(b, 85, 65535) },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			data := cabinetFixture(t, []byte("manifest"), false, false)
			mutate(data)
			index, err := indexCabinet(t.Context(), bytes.NewReader(data), int64(len(data)))
			if err != ErrFormat || index != (cabinetIndex{}) {
				t.Fatalf("accepted %+v, %v", index, err)
			}
		})
	}
}

func TestCabinetMultipleFolders(t *testing.T) {
	data := cabinetFixture(t, []byte("manifest"), false, false)
	// Insert a second folder descriptor and place each file in its own folder.
	data = append(append(append([]byte(nil), data[:44]...), make([]byte, 8)...), data[44:]...)
	put16(data, 26, 2)
	put32(data, 16, 52)
	put32(data, 36, 89)
	put32(data, 44, 105)
	put16(data, 48, 1)
	put32(data, 74, 0)
	put16(data, 78, 1)
	put16(data, 93, 8)
	put16(data, 95, 8)
	data = append(append(append([]byte(nil), data[:105]...), make([]byte, 8)...), data[105:]...)
	put16(data, 109, 4)
	put16(data, 111, 4)
	put32(data, 8, uint32(len(data)))
	if index, err := indexCabinet(t.Context(), bytes.NewReader(data), int64(len(data))); err != nil || index.manifestSize != 8 {
		t.Fatalf("two folders: %+v %v", index, err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { put32(b, 44, 89) },
		func(b []byte) { put16(b, 40, 2) },
		func(b []byte) { put16(b, 78, 0) },
		func(b []byte) { put32(b, 70, 5) },
	} {
		bad := append([]byte(nil), data...)
		mutate(bad)
		if _, err := indexCabinet(t.Context(), bytes.NewReader(bad), int64(len(bad))); err != ErrFormat {
			t.Fatal("overlapping or incomplete folder accepted")
		}
	}
}

func TestCabinetInputFailures(t *testing.T) {
	data := cabinetFixture(t, []byte("manifest"), false, false)
	for i := 0; i < len(data); i++ {
		if _, err := indexCabinet(t.Context(), bytes.NewReader(data[:i]), int64(i)); err != ErrFormat {
			t.Fatalf("accepted truncation %d", i)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := indexCabinet(ctx, bytes.NewReader(data), int64(len(data))); err != ErrFormat {
		t.Fatal("cancelled index")
	}
	if _, err := indexCabinet(nil, bytes.NewReader(data), int64(len(data))); err != ErrFormat {
		t.Fatal("nil context")
	}
	for _, r := range []io.ReaderAt{nil, &faultReader{ReaderAt: bytes.NewReader(data), fail: 1}, &faultReader{ReaderAt: bytes.NewReader(data), fail: 2}} {
		if _, err := indexCabinet(t.Context(), r, int64(len(data))); err != ErrFormat {
			t.Fatal("read failure accepted")
		}
	}
}

func FuzzCabinetIndex(f *testing.F) {
	f.Add(cabinetFixture(f, []byte("manifest"), false, false))
	f.Add(cabinetFixture(f, bytes.Repeat([]byte("manifest"), 5000), true, true))
	f.Fuzz(func(t *testing.T, data []byte) {
		index, err := indexCabinet(t.Context(), bytes.NewReader(data), int64(len(data)))
		if err != nil {
			if err != ErrFormat || index != (cabinetIndex{}) {
				t.Fatal("partial metadata")
			}
			return
		}
		if index.manifestSize < 1 || index.manifestSize > maxManifestSize || index.files < 1 || index.files > maxCabinetFiles {
			t.Fatal("unbounded directory")
		}
	})
}
