package burnbundle

import (
	"bytes"
	"context"
	"io"
	"strings"
)

const (
	maxManifestSize = int64(1 << 20)
	maxCabinetTable = int64(1 << 20)
	maxCabinetFiles = int64(4096)
	maxExpandedUX   = int64(512 << 20)
)

type cabinetIndex struct {
	manifestSize int64
	files        int64
}

type cabinetFolder struct {
	start, blocks, compression int64
	expanded, fileEnd          int64
	files                      int64
}

// indexCabinet validates every directory entry and compressed-block range before
// passing the cabinet to the native decoder. It never uses member names as paths.
func indexCabinet(ctx context.Context, reader io.ReaderAt, size int64) (cabinetIndex, error) {
	var empty cabinetIndex
	if ctx == nil || ctx.Err() != nil || reader == nil || size < 36 || size > maxUXSize {
		return empty, ErrFormat
	}
	r := boundedReader{reader, size}
	data := make([]byte, min(size, maxCabinetTable))
	if !r.read(0, data) || string(data[:4]) != "MSCF" || u32(data[8:]) != size || u32(data[4:]) != 0 || u32(data[12:]) != 0 || u32(data[20:]) != 0 || data[24] != 3 || data[25] != 1 {
		return empty, ErrFormat
	}
	folderCount, fileCount, flags := u16(data[26:]), u16(data[28:]), u16(data[30:])
	if folderCount < 1 || folderCount > 64 || fileCount < 1 || fileCount > maxCabinetFiles || (flags != 0 && flags != 4) || u16(data[34:]) != 0 {
		return empty, ErrFormat
	}
	offset, folderReserve, dataReserve := int64(36), int64(0), int64(0)
	if flags == 4 {
		if len(data) < 40 || u16(data[36:]) > 60000 {
			return empty, ErrFormat
		}
		offset = 40 + u16(data[36:])
		folderReserve, dataReserve = int64(data[38]), int64(data[39])
	}
	fileOffset := u32(data[16:])
	if offset+folderCount*(8+folderReserve) > fileOffset || fileOffset >= int64(len(data)) {
		return empty, ErrFormat
	}
	var folders [64]cabinetFolder
	for i := int64(0); i < folderCount; i++ {
		entry := data[offset : offset+8]
		folder := cabinetFolder{start: u32(entry), blocks: u16(entry[4:]), compression: u16(entry[6:])}
		if folder.start <= fileOffset || folder.start >= size || folder.blocks == 0 || !cabinetCompression(folder.compression) || i > 0 && folder.start <= folders[i-1].start {
			return empty, ErrFormat
		}
		folders[i] = folder
		offset += 8 + folderReserve
	}
	// Bounded metadata reads validate each folder's actual expanded extent. The
	// compressed bytes and checksums remain the native decoder's responsibility.
	var block [8]byte
	var blockCount, expanded int64
	for i := int64(0); i < folderCount; i++ {
		folder := &folders[i]
		limit := size
		if i+1 < folderCount {
			limit = folders[i+1].start
		}
		offset = folder.start
		for n := int64(0); n < folder.blocks; n++ {
			blockCount++
			if ctx.Err() != nil || blockCount > 65536 || !(region{offset, 8 + dataReserve}).within(limit) || !r.read(offset, block[:]) {
				return empty, ErrFormat
			}
			compressed, uncompressed := u16(block[4:]), u16(block[6:])
			if compressed == 0 || uncompressed == 0 || uncompressed > 32768 || folder.compression == 0 && compressed != uncompressed || !(region{offset + 8 + dataReserve, compressed}).within(limit) {
				return empty, ErrFormat
			}
			folder.expanded += uncompressed
			expanded += uncompressed
			if expanded > maxExpandedUX {
				return empty, ErrFormat
			}
			offset += 8 + dataReserve + compressed
		}
	}
	offset = fileOffset
	seen := make(map[string]bool, fileCount)
	lastFolder := int64(0)
	var result cabinetIndex
	for i := int64(0); i < fileCount; i++ {
		limit := min(int64(len(data)), folders[0].start)
		if ctx.Err() != nil || offset+17 > limit {
			return empty, ErrFormat
		}
		entry := data[offset : offset+16]
		length, start, folderID, attributes := u32(entry), u32(entry[4:]), u16(entry[8:]), u16(entry[14:])
		offset += 16
		nameEnd := bytes.IndexByte(data[offset:min(offset+257, limit)], 0)
		if nameEnd < 1 || nameEnd > 256 {
			return empty, ErrFormat
		}
		name := string(data[offset : offset+int64(nameEnd)])
		for _, ch := range []byte(name) {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.') {
				return empty, ErrFormat
			}
		}
		key := strings.ToLower(name)
		if name == "." || name == ".." || seen[key] || folderID < lastFolder || folderID >= folderCount || attributes & ^int64(0xa7) != 0 {
			return empty, ErrFormat
		}
		seen[key] = true
		folder := &folders[folderID]
		if start < folder.fileEnd || start > folder.expanded || length > folder.expanded-start {
			return empty, ErrFormat
		}
		if i == 0 {
			if name != "0" || folderID != 0 || start != 0 || length < 1 || length > maxManifestSize {
				return empty, ErrFormat
			}
			result = cabinetIndex{manifestSize: length, files: fileCount}
		}
		folder.fileEnd, folder.files, lastFolder = start+length, folder.files+1, folderID
		offset += int64(nameEnd) + 1
	}
	for i := int64(0); i < folderCount; i++ {
		if folders[i].files == 0 {
			return empty, ErrFormat
		}
	}
	return result, nil
}

func cabinetCompression(value int64) bool {
	// CAB stores the LZX window exponent in bits 8..12. No external or split
	// cabinets, Quantum codec or unknown option bits are admitted.
	return value == 0 || value == 1 || value & ^int64(0x1f0f) == 0 && value&15 == 3 && value>>8 >= 15 && value>>8 <= 21
}
