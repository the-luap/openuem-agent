package netbirdinstall

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const maxXARTOC = 128 << 10

// inspectMacArchive reads the retained descriptor, never archive paths. The
// outer package's approved SHA-256 and native signature bind these bytes; this
// parser is an identity check, not an alternative signature implementation.
func inspectMacArchive(parent context.Context, reader io.ReaderAt, size int64, descriptor packageapi.Package) error {
	return inspectMacArchiveEvidence(parent, reader, size, descriptor, nil)
}

func inspectMacArchiveEvidence(parent context.Context, reader io.ReaderAt, size int64, descriptor packageapi.Package, evidence map[string]installedFile) error {
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	entries, err := readXARTOC(ctx, reader, size)
	if err != nil {
		return ErrMetadata
	}
	err = inspectMacEvidence(ctx, descriptor, func(name string, limit int64, consume func(io.Reader) error) error {
		entry, exists := entries[name]
		if !exists || entry.size > limit || entry.length > limit {
			return ErrMetadata
		}
		section := io.NewSectionReader(reader, entry.offset, entry.length)
		var content io.Reader = contextReader{ctx, section}
		if entry.encoding == "application/x-gzip" {
			zipped, err := zlib.NewReader(content)
			if err != nil {
				return ErrMetadata
			}
			defer zipped.Close()
			content = contextReader{ctx, zipped}
		}
		bounded := &io.LimitedReader{R: content, N: entry.size + 1}
		if err := consume(bounded); err != nil {
			return ErrMetadata
		}
		var trailing [1]byte
		if n, err := bounded.Read(trailing[:]); n != 0 || err != io.EOF || bounded.N != 1 {
			return ErrMetadata
		}
		return nil
	}, evidence)
	return contextError(ctx, err)
}

type xarEntry struct {
	offset, length, size int64
	encoding             string
}

func readXARTOC(ctx context.Context, reader io.ReaderAt, size int64) (map[string]xarEntry, error) {
	var header [28]byte
	if size < 28 || size > 512<<20 {
		return nil, ErrMetadata
	}
	if _, err := reader.ReadAt(header[:], 0); err != nil || string(header[:4]) != "xar!" || binary.BigEndian.Uint16(header[4:6]) != 28 || binary.BigEndian.Uint16(header[6:8]) != 1 {
		return nil, ErrMetadata
	}
	compressed, uncompressed := binary.BigEndian.Uint64(header[8:16]), binary.BigEndian.Uint64(header[16:24])
	if compressed == 0 || compressed > maxXARTOC || uncompressed == 0 || uncompressed > maxXARTOC || compressed > uint64(size-28) {
		return nil, ErrMetadata
	}
	compressedData := make([]byte, int(compressed))
	if _, err := reader.ReadAt(compressedData, 28); err != nil {
		return nil, ErrMetadata
	}
	buffer := bytes.NewReader(compressedData)
	zipped, err := zlib.NewReader(buffer)
	if err != nil {
		return nil, ErrMetadata
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, zipped}, int64(uncompressed)+1))
	closeErr := zipped.Close()
	if err != nil || closeErr != nil || len(data) != int(uncompressed) || buffer.Len() != 0 {
		return nil, ErrMetadata
	}
	root, err := boundedXML(bytes.NewReader(data), maxXARTOC, true)
	if err != nil || root.name != "xar" {
		return nil, ErrMetadata
	}
	toc, ok := root.oneChild("toc")
	if !ok {
		return nil, ErrMetadata
	}
	entries := map[string]xarEntry{}
	seen := map[string]bool{}
	heap := int64(compressed) + 28
	var visit func(*xmlNode, string) bool
	visit = func(node *xmlNode, parent string) bool {
		name, nameOK := node.xarName()
		kind, kindOK := node.oneChild("type")
		if !nameOK || !kindOK || len(name.children) != 0 || len(kind.children) != 0 || name.text == "" || len(name.text) > 256 || name.text == "." || name.text == ".." || strings.ContainsAny(name.text, "/\\\x00\r\n") {
			return false
		}
		full := parent + name.text
		if len(full) > 1024 || seen[full] || len(seen) >= 128 {
			return false
		}
		seen[full] = true
		if kind.text == "directory" {
			for _, child := range node.children {
				if child.name == "data" || child.name == "file" && !visit(child, full+"/") {
					return false
				}
			}
			return true
		}
		if kind.text != "file" {
			return false
		}
		for _, child := range node.children {
			if child.name == "file" {
				return false
			}
		}
		body, ok := node.oneChild("data")
		if !ok {
			return false
		}
		number := func(key string) (int64, bool) {
			value, ok := body.oneChild(key)
			if !ok || len(value.children) != 0 || len(value.text) == 0 || len(value.text) > 12 {
				return 0, false
			}
			for _, c := range value.text {
				if c < '0' || c > '9' {
					return 0, false
				}
			}
			n, err := strconv.ParseInt(value.text, 10, 64)
			return n, err == nil
		}
		offset, offsetOK := number("offset")
		length, lengthOK := number("length")
		entrySize, sizeOK := number("size")
		encoding, encodingOK := body.oneChild("encoding")
		if !offsetOK || !lengthOK || !sizeOK || !encodingOK || length == 0 || entrySize == 0 || offset > size-heap || length > size-heap-offset || entrySize > 512<<20 {
			return false
		}
		style := encoding.attrs["style"]
		if style != "application/octet-stream" && style != "application/x-gzip" || style == "application/octet-stream" && length != entrySize {
			return false
		}
		entries[full] = xarEntry{heap + offset, length, entrySize, style}
		return true
	}
	for _, node := range toc.children {
		if node.name == "file" && !visit(node, "") {
			return nil, ErrMetadata
		}
	}
	if len(entries) == 0 {
		return nil, ErrMetadata
	}
	return entries, nil
}

func (n *xmlNode) oneChild(name string) (*xmlNode, bool) {
	var result *xmlNode
	for _, child := range n.children {
		if child.name == name {
			if result != nil {
				return nil, false
			}
			result = child
		}
	}
	return result, result != nil
}

// The signed v0.78.1 per-architecture PKG repeats identical name elements in
// several component entries. Accept only identical plain values; concatenating
// them (as some libarchive versions do) changes the path, while picking one
// conflicting value would make the metadata ambiguous.
func (n *xmlNode) xarName() (*xmlNode, bool) {
	var result *xmlNode
	for _, child := range n.children {
		if child.name != "name" {
			continue
		}
		if len(child.children) != 0 || len(child.attrs) != 0 || result != nil && result.text != child.text {
			return nil, false
		}
		result = child
	}
	return result, result != nil
}
