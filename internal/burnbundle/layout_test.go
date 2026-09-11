package burnbundle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

const fixtureCode = "{12345678-9ABC-DEF0-1234-56789ABCDEF0}"

func put16(data []byte, offset int, value uint16) {
	binary.LittleEndian.PutUint16(data[offset:], value)
}
func put32(data []byte, offset int, value uint32) {
	binary.LittleEndian.PutUint32(data[offset:], value)
}

// This inert fixture is assembled from the documented PE and Burn field layouts.
// It contains no machine code, installer, certificate or executable CAB member.
func layoutFixture(machine uint16) []byte {
	data := make([]byte, 2048+64)
	copy(data, "MZ")
	put32(data, 60, 128)
	copy(data[128:], "PE\x00\x00")
	put16(data, 132, machine)
	put16(data, 134, 3)
	put16(data, 148, 240)
	put16(data, 150, 0x22)
	put16(data, 152, 0x20b)
	directory := 264
	if machine == 0x14c {
		put16(data, 148, 224)
		put16(data, 152, 0x10b)
		directory = 248
	}
	put32(data, 184, 4096)
	put32(data, 188, 512)
	put32(data, 208, 16384)
	put32(data, 212, 512)
	put16(data, 220, 2)
	put32(data, directory-4, 16)
	section := 152 + int(binary.LittleEndian.Uint16(data[148:]))
	for i, name := range []string{".text", ".rdata", ".wixburn"} {
		header := section + i*40
		copy(data[header:], name)
		put32(data, header+8, 256)
		put32(data, header+12, uint32(4096*(i+1)))
		put32(data, header+16, 512)
		put32(data, header+20, uint32(512*(i+1)))
		put32(data, header+36, 0x40000040)
	}
	put32(data, 1536, 0x00f14300)
	put32(data, 1540, 2)
	copy(data[1544:], []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0})
	put32(data, 1560, 2048)
	put32(data, 1576, 1)
	put32(data, 1580, 1)
	put32(data, 1584, 64)
	copy(data[2048:], "MSCF")
	put32(data, 2056, 64)
	data[2072], data[2073] = 3, 1
	return data
}

func TestInspectArchitecturesAndGUIDByteOrder(t *testing.T) {
	for machine, architecture := range map[uint16]string{0x14c: "386", 0x8664: "amd64", 0xaa64: "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			data := layoutFixture(machine)
			got, err := Inspect(bytes.NewReader(data), int64(len(data)))
			want := Layout{Architecture: architecture, BundleCode: fixtureCode, UXOffset: 2048, UXSize: 64}
			if err != nil || got != want {
				t.Fatalf("layout = %+v, %v; want %+v", got, err, want)
			}
		})
	}
}

func TestInspectCertificateRangesAndAdditionalContainers(t *testing.T) {
	for _, mode := range []string{"final", "original", "same", "separate", "attached", "detached", "bss"} {
		t.Run(mode, func(t *testing.T) {
			data := append(layoutFixture(0x8664), make([]byte, 128)...)
			if mode == "final" || mode == "same" || mode == "separate" {
				put32(data, 296, 2144)
				put32(data, 300, 32)
			}
			if mode == "original" || mode == "same" || mode == "separate" {
				offset := uint32(2144)
				if mode == "separate" {
					offset = 2112
				}
				put32(data, 1568, offset)
				put32(data, 1572, 32)
			}
			if mode == "attached" || mode == "detached" {
				put32(data, 1580, 2)
				put32(data, 1588, 128)
				if mode == "detached" {
					data = data[:2112]
				}
			}
			if mode == "bss" {
				put32(data, 432+16, 0)
				put32(data, 432+20, 0)
			}
			if _, err := Inspect(bytes.NewReader(data), int64(len(data))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInspectRejectsAmbiguousAndOutOfBoundsLayouts(t *testing.T) {
	changes := map[string]func([]byte){
		"DOS signature":                 func(b []byte) { b[0] = 0 },
		"PE signature":                  func(b []byte) { b[128] = 0 },
		"PE before DOS end":             func(b []byte) { put32(b, 60, 32) },
		"PE offset overflow":            func(b []byte) { put32(b, 60, 0xfffffff8) },
		"PE misalignment":               func(b []byte) { put32(b, 60, 129) },
		"unknown architecture":          func(b []byte) { put16(b, 132, 0xa641) },
		"architecture format mismatch":  func(b []byte) { put16(b, 132, 0x14c) },
		"no sections":                   func(b []byte) { put16(b, 134, 0) },
		"too many sections":             func(b []byte) { put16(b, 134, 97) },
		"object file":                   func(b []byte) { put16(b, 150, 0) },
		"DLL":                           func(b []byte) { put16(b, 150, 0x2002) },
		"system image":                  func(b []byte) { put16(b, 150, 0x1002) },
		"short optional header":         func(b []byte) { put16(b, 148, 239) },
		"huge optional header":          func(b []byte) { put16(b, 148, 65535) },
		"optional magic":                func(b []byte) { put16(b, 152, 0x10b) },
		"directory count":               func(b []byte) { put32(b, 260, 17) },
		"section alignment":             func(b []byte) { put32(b, 184, 513) },
		"small section alignment":       func(b []byte) { put32(b, 184, 256) },
		"zero file alignment":           func(b []byte) { put32(b, 188, 0) },
		"file alignment":                func(b []byte) { put32(b, 188, 513) },
		"huge file alignment":           func(b []byte) { put32(b, 188, 1<<20) },
		"image size":                    func(b []byte) { put32(b, 208, 8192) },
		"image alignment":               func(b []byte) { put32(b, 208, 16383) },
		"header truncates sections":     func(b []byte) { put32(b, 212, 0) },
		"header exceeds file":           func(b []byte) { put32(b, 212, 4096) },
		"header alignment":              func(b []byte) { put32(b, 212, 513) },
		"missing Burn section":          func(b []byte) { b[472] = 'x' },
		"duplicate Burn section":        func(b []byte) { copy(b[432:440], ".wixburn") },
		"raw overlap":                   func(b []byte) { put32(b, 492, 1024) },
		"raw inside header":             func(b []byte) { put32(b, 492, 0) },
		"raw range overflow":            func(b []byte) { put32(b, 488, 0xfffffe00) },
		"raw offset overflow":           func(b []byte) { put32(b, 492, 0xfffffe00) },
		"raw unaligned":                 func(b []byte) { put32(b, 492, 1537) },
		"raw size unaligned":            func(b []byte) { put32(b, 488, 511) },
		"virtual overlap":               func(b []byte) { put32(b, 484, 8192) },
		"virtual inside header":         func(b []byte) { put32(b, 484, 0) },
		"virtual unaligned":             func(b []byte) { put32(b, 484, 12289) },
		"virtual overflow":              func(b []byte) { put32(b, 480, 0xffffffff) },
		"virtual header truncation":     func(b []byte) { put32(b, 480, 51) },
		"BSS with raw pointer":          func(b []byte) { put32(b, 448, 0) },
		"Burn magic":                    func(b []byte) { put32(b, 1536, 0) },
		"unknown Burn version":          func(b []byte) { put32(b, 1540, 3) },
		"zero GUID":                     func(b []byte) { clear(b[1544:1560]) },
		"non CAB format":                func(b []byte) { put32(b, 1576, 2) },
		"no containers":                 func(b []byte) { put32(b, 1580, 0) },
		"excessive containers":          func(b []byte) { put32(b, 1580, 65) },
		"empty attached container":      func(b []byte) { put32(b, 1580, 2) },
		"table exceeds virtual section": func(b []byte) { put32(b, 480, 52); put32(b, 1580, 2); put32(b, 1588, 64) },
		"UX inside sections":            func(b []byte) { put32(b, 1560, 1536) },
		"UX offset overflow":            func(b []byte) { put32(b, 1560, 0xffffffff) },
		"UX size overflow":              func(b []byte) { put32(b, 1584, 0xffffffff) },
		"UX beyond EOF":                 func(b []byte) { put32(b, 1584, 65) },
		"UX too small":                  func(b []byte) { put32(b, 1584, 35) },
		"cabinet signature":             func(b []byte) { b[2048] = 0 },
		"cabinet length mismatch":       func(b []byte) { put32(b, 2056, 63) },
		"certificate offset only":       func(b []byte) { put32(b, 296, 2056) },
		"certificate size only":         func(b []byte) { put32(b, 300, 8) },
		"certificate overlaps UX":       func(b []byte) { put32(b, 296, 2056); put32(b, 300, 8) },
		"certificate overlaps section":  func(b []byte) { put32(b, 296, 1536); put32(b, 300, 8) },
		"certificate overlaps header":   func(b []byte) { put32(b, 296, 64); put32(b, 300, 8) },
		"certificate past EOF":          func(b []byte) { put32(b, 296, 2112); put32(b, 300, 8) },
		"original overlaps UX":          func(b []byte) { put32(b, 1568, 2056); put32(b, 1572, 8) },
		"original overlaps section":     func(b []byte) { put32(b, 1568, 1536); put32(b, 1572, 8) },
		"original offset only":          func(b []byte) { put32(b, 1568, 2056) },
		"original size only":            func(b []byte) { put32(b, 1572, 8) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			data := layoutFixture(0x8664)
			change(data)
			layout, err := Inspect(bytes.NewReader(data), int64(len(data)))
			if err != ErrFormat || layout != (Layout{}) {
				t.Fatalf("malformed layout returned %+v, %v", layout, err)
			}
		})
	}
}

func TestInspectBoundedContainerTable(t *testing.T) {
	data := layoutFixture(0x8664)
	put32(data, 480, 512)
	put32(data, 1580, 64)
	for i := 1; i < 64; i++ {
		put32(data, 1584+i*4, 1)
	}
	r := &trackedReader{ReaderAt: bytes.NewReader(data), size: int64(len(data))}
	if _, err := Inspect(r, r.size); err != nil {
		t.Fatal(err)
	}
	put32(data, 480, 303)
	if _, err := Inspect(bytes.NewReader(data), int64(len(data))); err != ErrFormat {
		t.Fatal("table exceeds virtual section")
	}
	put32(data, 480, 512)
	put32(data, 1580, 65)
	if _, err := Inspect(bytes.NewReader(data), int64(len(data))); err != ErrFormat {
		t.Fatal("too many containers")
	}
}

func TestInspectRejectsCertificateAmbiguity(t *testing.T) {
	for name, ranges := range map[string][4]uint32{
		"overlapping":        {2112, 32, 2120, 32},
		"unaligned final":    {2113, 32, 0, 0},
		"unaligned original": {0, 0, 2113, 32},
		"short final":        {2112, 7, 0, 0},
		"short original":     {0, 0, 2112, 7},
		"past EOF original":  {0, 0, 2232, 16},
	} {
		t.Run(name, func(t *testing.T) {
			data := append(layoutFixture(0x8664), make([]byte, 128)...)
			put32(data, 296, ranges[0])
			put32(data, 300, ranges[1])
			put32(data, 1568, ranges[2])
			put32(data, 1572, ranges[3])
			if _, err := Inspect(bytes.NewReader(data), int64(len(data))); err != ErrFormat {
				t.Fatal("ambiguous certificate ranges")
			}
		})
	}
}

func TestInspectRequiresCompleteFileAndReads(t *testing.T) {
	data := layoutFixture(0x8664)
	for length := 0; length < len(data); length++ {
		if _, err := Inspect(bytes.NewReader(data[:length]), int64(length)); err != ErrFormat {
			t.Fatalf("accepted file truncated at %d", length)
		}
	}
	for _, size := range []int64{-1, 0, maxBundleSize + 1, 1<<63 - 1} {
		if _, err := Inspect(bytes.NewReader(data), size); err != ErrFormat {
			t.Fatalf("accepted size %d", size)
		}
	}
	if _, err := Inspect(nil, int64(len(data))); err != ErrFormat {
		t.Fatal("nil reader accepted")
	}
	for read := 1; read <= 7; read++ {
		for _, full := range []bool{false, true} {
			r := &faultReader{ReaderAt: bytes.NewReader(data), fail: read, full: full}
			layout, err := Inspect(r, int64(len(data)))
			if err != ErrFormat || layout != (Layout{}) {
				t.Fatalf("read failure %d: %+v, %v", read, layout, err)
			}
		}
	}
}

type faultReader struct {
	io.ReaderAt
	fail, calls int
	full        bool
}

func (r *faultReader) ReadAt(p []byte, off int64) (int, error) {
	r.calls++
	if r.calls == r.fail {
		if r.full {
			n, _ := r.ReaderAt.ReadAt(p, off)
			return n, errors.New("private path and details must not escape")
		}
		return 0, io.ErrUnexpectedEOF
	}
	return r.ReaderAt.ReadAt(p, off)
}

type trackedReader struct {
	io.ReaderAt
	size, bytes int64
	calls       int
}

func (r *trackedReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || int64(len(p)) > r.size-off {
		panic("out-of-bounds read")
	}
	r.bytes += int64(len(p))
	r.calls++
	if r.bytes > 5000 || r.calls > 7 {
		panic("unbounded metadata reads")
	}
	return r.ReaderAt.ReadAt(p, off)
}

func TestInspectDoesNotReadPayloadsSymbolsOrCertificates(t *testing.T) {
	data := append(layoutFixture(0x8664), make([]byte, 8)...)
	put32(data, 140, 0xfffffff0) // COFF symbol/string tables are never followed.
	put32(data, 144, 0xffffffff)
	put32(data, 296, 2112)
	put32(data, 300, 8)
	r := &trackedReader{ReaderAt: bytes.NewReader(data[:2084]), size: int64(len(data))}
	if _, err := Inspect(r, r.size); err != nil {
		t.Fatal(err)
	}
	if r.calls != 7 || r.bytes >= 1024 {
		t.Fatalf("unexpected header reads: %d / %d", r.calls, r.bytes)
	}
}

func FuzzInspect(f *testing.F) {
	for _, machine := range []uint16{0x14c, 0x8664, 0xaa64} {
		f.Add(layoutFixture(machine))
	}
	f.Add([]byte("MZ"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &trackedReader{ReaderAt: bytes.NewReader(data), size: int64(len(data))}
		layout, err := Inspect(r, r.size)
		if err != nil {
			if err != ErrFormat || layout != (Layout{}) {
				t.Fatal("partial metadata or unredacted error")
			}
			return
		}
		if layout.BundleCode == "" || layout.UXOffset < 512 || layout.UXSize < 36 || layout.UXSize > maxUXSize || layout.UXOffset > int64(len(data))-layout.UXSize {
			t.Fatal("invalid accepted layout")
		}
	})
}
