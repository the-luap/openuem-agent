// Package burnbundle reads bounded Burn metadata without executing or extracting
// an installer. Metadata inspection does not establish trust or grant execution.
package burnbundle

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var ErrFormat = errors.New("unsupported or malformed Burn bundle layout")

const (
	maxBundleSize = int64(8 << 30)
	maxHeaderSize = int64(1 << 20)
	maxUXSize     = int64(64 << 20)
	maxContainers = int64(64)
)

// Layout identifies the bootstrapper architecture, section-declared bundle code
// and UX cabinet range. It does not prove the embedded registration, payload
// architecture, scope, display version, registry view or package authenticity.
type Layout struct {
	Architecture string
	BundleCode   string
	UXOffset     int64
	UXSize       int64
}

type region struct{ offset, size int64 }

func (r region) within(size int64) bool {
	return r.offset >= 0 && r.size > 0 && r.offset <= size && r.size <= size-r.offset
}

func (r region) overlaps(other region) bool {
	return r.size > 0 && other.size > 0 && r.offset < other.offset+other.size && other.offset < r.offset+r.size
}

type boundedReader struct {
	reader io.ReaderAt
	size   int64
}

func (r boundedReader) read(offset int64, dst []byte) bool {
	if !(region{offset, int64(len(dst))}).within(r.size) {
		return false
	}
	n, err := r.reader.ReadAt(dst, offset)
	return n == len(dst) && err == nil
}

func u16(b []byte) int64      { return int64(binary.LittleEndian.Uint16(b)) }
func u32(b []byte) int64      { return int64(binary.LittleEndian.Uint32(b)) }
func powerOfTwo(n int64) bool { return n > 0 && n&(n-1) == 0 }

// Inspect locates a version-2 .wixburn UX cabinet in a stable ReaderAt. Callers
// must retain the same protected file across inspection and later verification.
// Reads and allocations are bounded independently of the declared file size.
// No cabinet payload or certificate body is read, decompressed or interpreted.
func Inspect(reader io.ReaderAt, size int64) (Layout, error) {
	var empty Layout
	if reader == nil || size < 512 || size > maxBundleSize {
		return empty, ErrFormat
	}
	r := boundedReader{reader, size}
	var dos [64]byte
	if !r.read(0, dos[:]) || string(dos[:2]) != "MZ" {
		return empty, ErrFormat
	}
	peOffset := u32(dos[60:])
	var coff [24]byte
	if peOffset < 64 || peOffset > maxHeaderSize || peOffset%8 != 0 || !r.read(peOffset, coff[:]) || string(coff[:4]) != "PE\x00\x00" {
		return empty, ErrFormat
	}
	architecture := map[int64]string{0x14c: "386", 0x8664: "amd64", 0xaa64: "arm64"}[u16(coff[4:])]
	count, optionalSize, flags := u16(coff[6:]), u16(coff[20:]), u16(coff[22:])
	if architecture == "" || count < 1 || count > 96 || flags&2 == 0 || flags&0x3000 != 0 {
		return empty, ErrFormat
	}
	expectedSize, expectedMagic, directoryOffset := int64(240), int64(0x20b), 112
	if architecture == "386" {
		expectedSize, expectedMagic, directoryOffset = 224, 0x10b, 96
	}
	if optionalSize != expectedSize {
		return empty, ErrFormat
	}
	var optional [240]byte
	if !r.read(peOffset+24, optional[:optionalSize]) || u16(optional[:]) != expectedMagic || u32(optional[directoryOffset-4:]) != 16 {
		return empty, ErrFormat
	}
	sectionAlignment, fileAlignment := u32(optional[32:]), u32(optional[36:])
	headerSize, imageSize := u32(optional[60:]), u32(optional[56:])
	sectionOffset := peOffset + 24 + optionalSize
	if !powerOfTwo(fileAlignment) || fileAlignment < 512 || fileAlignment > 65536 || !powerOfTwo(sectionAlignment) || sectionAlignment < fileAlignment || sectionAlignment > maxHeaderSize || headerSize%fileAlignment != 0 || headerSize < sectionOffset+count*40 || headerSize > maxHeaderSize || headerSize > size || imageSize%sectionAlignment != 0 || imageSize < headerSize {
		return empty, ErrFormat
	}
	certificateOffset := directoryOffset + 4*8 // The security directory uses a file offset, not an RVA.
	certificate := region{u32(optional[certificateOffset:]), u32(optional[certificateOffset+4:])}
	if !validCertificateRange(certificate, size) {
		return empty, ErrFormat
	}
	var sections [96 * 40]byte
	if !r.read(sectionOffset, sections[:count*40]) {
		return empty, ErrFormat
	}
	rawRanges := []region{{0, headerSize}}
	virtualRanges := []region{{0, headerSize}}
	var burn region
	var burnVirtualSize int64
	stubMinimum := headerSize
	for i := int64(0); i < count; i++ {
		header := sections[i*40 : (i+1)*40]
		raw := region{u32(header[20:]), u32(header[16:])}
		virtual := region{u32(header[12:]), max(u32(header[8:]), raw.size)}
		if virtual.offset%sectionAlignment != 0 || !virtual.within(imageSize) || overlapsAny(virtual, virtualRanges) {
			return empty, ErrFormat
		}
		virtualRanges = append(virtualRanges, virtual)
		if raw.size > 0 {
			if raw.offset%fileAlignment != 0 || raw.size%fileAlignment != 0 || !raw.within(size) || overlapsAny(raw, rawRanges) || raw.overlaps(certificate) {
				return empty, ErrFormat
			}
			rawRanges = append(rawRanges, raw)
			stubMinimum = max(stubMinimum, raw.offset+raw.size)
		} else if raw.offset != 0 {
			return empty, ErrFormat
		}
		if string(header[:8]) == ".wixburn" {
			if burn.size != 0 || raw.size < 52 || u32(header[8:]) < 52 {
				return empty, ErrFormat
			}
			burn = raw
			burnVirtualSize = u32(header[8:])
		}
	}
	if burn.size == 0 || certificate.overlaps(rawRanges[0]) {
		return empty, ErrFormat
	}
	var metadata [52]byte
	if !r.read(burn.offset, metadata[:]) || u32(metadata[:]) != 0x00f14300 || u32(metadata[4:]) != 2 || u32(metadata[40:]) != 1 {
		return empty, ErrFormat
	}
	containers := u32(metadata[44:])
	if containers < 1 || containers > maxContainers || containers > (min(burn.size, burnVirtualSize)-48)/4 {
		return empty, ErrFormat
	}
	// Validate the bounded declaration table without following attached payloads.
	var lengths [maxContainers * 4]byte
	if !r.read(burn.offset+48, lengths[:containers*4]) {
		return empty, ErrFormat
	}
	for i := int64(0); i < containers; i++ {
		if u32(lengths[i*4:]) == 0 {
			return empty, ErrFormat
		}
	}
	ux := region{u32(metadata[24:]), u32(metadata[48:])}
	originalCertificate := region{u32(metadata[32:]), u32(metadata[36:])}
	if ux.offset < stubMinimum || ux.size < 36 || ux.size > maxUXSize || !ux.within(size) || !validCertificateRange(originalCertificate, size) || ux.overlaps(certificate) || ux.overlaps(originalCertificate) || overlapsAny(originalCertificate, rawRanges) {
		return empty, ErrFormat
	}
	if certificate.size != 0 && certificate.offset < ux.offset+ux.size || originalCertificate.size != 0 && originalCertificate.offset < ux.offset+ux.size || originalCertificate != certificate && originalCertificate.overlaps(certificate) {
		return empty, ErrFormat
	}
	var cabinet [36]byte
	if !r.read(ux.offset, cabinet[:]) || string(cabinet[:4]) != "MSCF" || u32(cabinet[8:]) != ux.size {
		return empty, ErrFormat
	}
	guid := metadata[8:24]
	if string(guid) == string(make([]byte, 16)) {
		return empty, ErrFormat
	}
	code := fmt.Sprintf("{%08X-%04X-%04X-%X-%X}", u32(guid), u16(guid[4:]), u16(guid[6:]), guid[8:10], guid[10:16])
	return Layout{Architecture: architecture, BundleCode: code, UXOffset: ux.offset, UXSize: ux.size}, nil
}

func overlapsAny(r region, ranges []region) bool {
	for _, other := range ranges {
		if r.overlaps(other) {
			return true
		}
	}
	return false
}

func validCertificateRange(r region, size int64) bool {
	return r == (region{}) || r.offset > 0 && r.offset%8 == 0 && r.size >= 8 && r.within(size)
}
