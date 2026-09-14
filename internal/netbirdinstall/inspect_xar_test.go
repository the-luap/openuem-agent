package netbirdinstall

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func ownedZlib(data []byte) []byte {
	var buffer bytes.Buffer
	w := zlib.NewWriter(&buffer)
	_, _ = w.Write(data)
	_ = w.Close()
	return buffer.Bytes()
}

func ownedXAR(change func(string) string) []byte {
	return ownedXARInfo(change, `<pkg-info identifier="io.netbird.client" version="0.78.1"/>`)
}

func ownedXARInfo(change func(string) string, packageInfo string) []byte {
	var heap bytes.Buffer
	entry := func(name string, data []byte, compress bool) string {
		offset, size, encoding := heap.Len(), len(data), "application/octet-stream"
		if compress {
			data = ownedZlib(data)
			encoding = "application/x-gzip"
		}
		heap.Write(data)
		return fmt.Sprintf(`<file><name>%s</name><type>file</type><data><offset>%d</offset><length>%d</length><size>%d</size><encoding style="%s"/></data></file>`, name, offset, len(data), size, encoding)
	}
	distribution := entry("Distribution", []byte(ownedDistribution), true)
	info := entry("PackageInfo", []byte(packageInfo), true)
	payload := entry("Payload", ownedPayload(ownedExecutables(), 0), false)
	toc := `<xar><toc>` + distribution + `<file><name>netbird_arm64.pkg</name><type>directory</type>` + info + payload + `</file></toc></xar>`
	if change != nil {
		toc = change(toc)
	}
	compressed := ownedZlib([]byte(toc))
	header := make([]byte, 28)
	copy(header, "xar!")
	binary.BigEndian.PutUint16(header[4:], 28)
	binary.BigEndian.PutUint16(header[6:], 1)
	binary.BigEndian.PutUint64(header[8:], uint64(len(compressed)))
	binary.BigEndian.PutUint64(header[16:], uint64(len(toc)))
	return append(append(header, compressed...), heap.Bytes()...)
}

func TestXARIdentityFromBoundedRetainedBytes(t *testing.T) {
	for _, change := range []string{"none", "same-name", "signature", "conflicting-name", "duplicate-type", "duplicate-offset", "negative-offset", "large-offset", "large-length", "large-size", "encoding", "linked", "traversal", "duplicate-entry", "doctype", "wrong-toc-size", "wrong-compressed-size", "header-version", "truncated", "compressed-tail"} {
		t.Run(change, func(t *testing.T) {
			data := ownedXAR(func(toc string) string {
				switch change {
				case "same-name":
					return strings.Replace(toc, "<name>PackageInfo</name>", "<name>PackageInfo</name><name>PackageInfo</name>", 1)
				case "signature":
					return strings.Replace(toc, "<toc>", `<toc><signature><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>owned inert certificate data</X509Certificate></X509Data></KeyInfo></signature>`, 1)
				case "conflicting-name":
					return strings.Replace(toc, "<name>PackageInfo</name>", "<name>PackageInfo</name><name>Other</name>", 1)
				case "duplicate-type":
					return strings.Replace(toc, "<type>file</type>", "<type>file</type><type>file</type>", 1)
				case "duplicate-offset":
					return strings.Replace(toc, "<offset>0</offset>", "<offset>0</offset><offset>0</offset>", 1)
				case "negative-offset":
					return strings.Replace(toc, "<offset>0</offset>", "<offset>-1</offset>", 1)
				case "large-offset":
					return strings.Replace(toc, "<offset>0</offset>", "<offset>999999999999</offset>", 1)
				case "large-length":
					return strings.Replace(toc, "<length>", "<length>999999999999", 1)
				case "large-size":
					return strings.Replace(toc, "<size>", "<size>999999999999", 1)
				case "encoding":
					return strings.Replace(toc, "application/x-gzip", "application/unsupported", 1)
				case "linked":
					return strings.Replace(toc, "<type>file</type>", "<type>symlink</type>", 1)
				case "traversal":
					return strings.Replace(toc, "<name>PackageInfo</name>", "<name>../PackageInfo</name>", 1)
				case "duplicate-entry":
					return strings.Replace(toc, "</toc>", "<file><name>Distribution</name><type>directory</type></file></toc>", 1)
				case "doctype":
					return "<!DOCTYPE xar>" + toc
				}
				return toc
			})
			switch change {
			case "wrong-toc-size":
				binary.BigEndian.PutUint64(data[16:], 1)
			case "wrong-compressed-size":
				binary.BigEndian.PutUint64(data[8:], maxXARTOC+1)
			case "header-version":
				data[7] = 2
			case "truncated":
				data = data[:len(data)-1]
			case "compressed-tail":
				binary.BigEndian.PutUint64(data[8:], binary.BigEndian.Uint64(data[8:16])+1)
			}
			err := inspectMacArchive(t.Context(), bytes.NewReader(data), int64(len(data)), metadataDescriptor("pkg"))
			if change == "none" || change == "same-name" || change == "signature" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func FuzzXARMetadata(f *testing.F) {
	f.Add(ownedXAR(nil))
	f.Add([]byte("xar!inert"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) <= 1<<20 {
			_ = inspectMacArchive(t.Context(), bytes.NewReader(data), int64(len(data)), metadataDescriptor("pkg"))
		}
	})
}
