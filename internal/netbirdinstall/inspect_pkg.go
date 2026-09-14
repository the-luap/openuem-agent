package netbirdinstall

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/xml"
	"io"
	"path"
	"strconv"
	"strings"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const maxPackageXML = 32 << 10
const maxPackagePayload = 256 << 20

func inspectMac(ctx context.Context, descriptor packageapi.Package, member func(string, int64, func(io.Reader) error) error) error {
	var component string
	err := member("Distribution", maxPackageXML, func(reader io.Reader) error {
		root, err := packageXML(reader)
		if err != nil {
			return err
		}
		component, err = distributionComponent(root, descriptor)
		return err
	})
	if err != nil {
		return ErrMetadata
	}
	err = member(component+"/PackageInfo", maxPackageXML, func(reader io.Reader) error {
		root, err := packageXML(reader)
		if err != nil || root.name != "pkg-info" || root.attrs["identifier"] != descriptor.PackageID || root.attrs["version"] != descriptor.Version {
			return ErrMetadata
		}
		return nil
	})
	if err != nil {
		return ErrMetadata
	}
	return member(component+"/Payload", 512<<20, func(reader io.Reader) error {
		return inspectPayload(ctx, reader, descriptor.Architecture)
	})
}

// xmlNode deliberately rejects namespaces, duplicate attributes, directives,
// multiple roots and excessive depth. Encoding/xml's normal struct decoding
// otherwise accepts duplicate singleton elements and silently picks a value.
type xmlNode struct {
	name     string
	attrs    map[string]string
	children []*xmlNode
	text     string
}

func packageXML(reader io.Reader) (*xmlNode, error) {
	return boundedXML(reader, maxPackageXML, false)
}

func boundedXML(reader io.Reader, limit int64, xarSignature bool) (*xmlNode, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, ErrMetadata
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var root *xmlNode
	var stack []*xmlNode
	declaration := false
	for count := 0; count < 4096; count++ {
		token, err := decoder.Token()
		if err == io.EOF && root != nil && len(stack) == 0 {
			return root, nil
		}
		if err != nil {
			return nil, ErrMetadata
		}
		switch t := token.(type) {
		case xml.StartElement:
			// XAR embeds public XMLDSIG certificate data. Preserve a qualified
			// name so signature elements can never alias package/TOC fields.
			signature := xarSignature && t.Name.Space == "http://www.w3.org/2000/09/xmldsig#" && (t.Name.Local == "KeyInfo" || t.Name.Local == "X509Data" || t.Name.Local == "X509Certificate")
			if t.Name.Space != "" && !signature || len(stack) >= 24 || len(stack) == 0 && root != nil {
				return nil, ErrMetadata
			}
			node := &xmlNode{name: t.Name.Local, attrs: make(map[string]string)}
			if signature {
				node.name = "signature:" + node.name
			}
			for _, attr := range t.Attr {
				if signature && attr.Name.Local == "xmlns" && attr.Name.Space == "" && attr.Value == t.Name.Space {
					continue
				}
				if _, exists := node.attrs[attr.Name.Local]; exists || attr.Name.Space != "" || attr.Name.Local == "xmlns" {
					return nil, ErrMetadata
				}
				node.attrs[attr.Name.Local] = attr.Value
			}
			if len(stack) == 0 {
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, ErrMetadata
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(t)) != "" {
					return nil, ErrMetadata
				}
			} else {
				stack[len(stack)-1].text += string(t)
			}
		case xml.ProcInst:
			if t.Target != "xml" || root != nil || declaration {
				return nil, ErrMetadata
			}
			declaration = true
		case xml.Comment:
		default:
			return nil, ErrMetadata
		}
	}
	return nil, ErrMetadata
}

func distributionComponent(root *xmlNode, descriptor packageapi.Package) (string, error) {
	if root == nil || root.name != "installer-gui-script" {
		return "", ErrMetadata
	}
	var component string
	products, options := 0, 0
	var visit func(*xmlNode) bool
	visit = func(node *xmlNode) bool {
		switch node.name {
		case "installer-gui-script", "choices-outline", "line", "choice", "bundle-version", "bundle":
		case "product":
			products++
			if node.attrs["id"] != descriptor.PackageID || node.attrs["version"] != descriptor.Version {
				return false
			}
		case "options":
			options++
			if node.attrs["require-scripts"] != "false" {
				return false
			}
			wanted := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[descriptor.Architecture]
			found := false
			seen := map[string]bool{}
			for _, architecture := range strings.Split(node.attrs["hostArchitectures"], ",") {
				if seen[architecture] || architecture != "x86_64" && architecture != "arm64" {
					return false
				}
				seen[architecture] = true
				found = found || architecture == wanted
			}
			if !found {
				return false
			}
		case "pkg-ref":
			if node.attrs["id"] != descriptor.PackageID || node.attrs["version"] != "" && node.attrs["version"] != descriptor.Version {
				return false
			}
			if value := strings.TrimSpace(node.text); value != "" {
				if component != "" || node.attrs["version"] != descriptor.Version || !strings.HasPrefix(value, "#") {
					return false
				}
				component = strings.TrimPrefix(value, "#")
				if len(component) > 128 || !strings.HasSuffix(component, ".pkg") || !strings.HasPrefix(component, "netbird") {
					return false
				}
				for _, c := range component {
					if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
						return false
					}
				}
			}
		default:
			// In particular, do not accept distribution JavaScript or external
			// package sources as a single-component native identity receipt.
			return false
		}
		for _, child := range node.children {
			if !visit(child) {
				return false
			}
		}
		return true
	}
	if !visit(root) || component == "" || products != 1 || options != 1 {
		return "", ErrMetadata
	}
	return component, nil
}

// inspectPayload supports the gzip/odc payload used by the vendor's individual
// architecture PKGs. It streams without extraction and requires exactly one
// ordinary, unlinked Mach-O executable for both the client and UI. Universal,
// differently encoded or ambiguous packages fail closed for explicit review.
func inspectPayload(ctx context.Context, reader io.Reader, architecture string) error {
	zipped, err := gzip.NewReader(contextReader{ctx, reader})
	if err != nil {
		return ErrMetadata
	}
	defer zipped.Close()
	raw := &io.LimitedReader{R: contextReader{ctx, zipped}, N: maxPackagePayload + 1}
	seen := map[string]bool{}
	targets := map[string]bool{"Applications/NetBird.app/Contents/MacOS/netbird": false, "Applications/NetBird.app/Contents/MacOS/netbird-ui": false}
	for entries := 0; entries < 1024; entries++ {
		var header [76]byte
		if _, err := io.ReadFull(raw, header[:]); err != nil || string(header[:6]) != "070707" {
			return ErrMetadata
		}
		// odc fields are strict octal ASCII, without newc alignment padding.
		for _, c := range header[6:] {
			if c < '0' || c > '7' {
				return ErrMetadata
			}
		}
		number := func(start, end int) int64 {
			value, _ := strconv.ParseInt(string(header[start:end]), 8, 64)
			return value
		}
		nameSize, size, mode, links := number(59, 65), number(65, 76), number(18, 24), number(36, 42)
		if nameSize < 2 || nameSize > 1024 || size > maxPackagePayload {
			return ErrMetadata
		}
		nameBytes := make([]byte, nameSize)
		if _, err := io.ReadFull(raw, nameBytes); err != nil || nameBytes[len(nameBytes)-1] != 0 || bytes.IndexByte(nameBytes[:len(nameBytes)-1], 0) >= 0 {
			return ErrMetadata
		}
		name := string(nameBytes[:len(nameBytes)-1])
		if name == "TRAILER!!!" {
			if size != 0 || !targets["Applications/NetBird.app/Contents/MacOS/netbird"] || !targets["Applications/NetBird.app/Contents/MacOS/netbird-ui"] {
				return ErrMetadata
			}
			padding, err := io.ReadAll(io.LimitReader(raw, 513))
			if err != nil || len(padding) > 511 || raw.N <= 0 || !bytes.Equal(padding, make([]byte, len(padding))) {
				return ErrMetadata
			}
			return nil
		}
		name = strings.TrimPrefix(name, "./")
		// The supported vendor layout is ASCII and contains ordinary files
		// and directories only. Reject aliases on case-insensitive volumes
		// and linked ancestors that could change the installed target paths.
		for _, c := range name {
			if c < 0x20 || c > 0x7e {
				return ErrMetadata
			}
		}
		key := strings.ToLower(name)
		if name == "" || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\r\n") || seen[key] {
			return ErrMetadata
		}
		kind := mode & 0170000
		if kind != 0100000 && kind != 0040000 || kind == 0100000 && links != 1 || kind == 0040000 && size != 0 {
			return ErrMetadata
		}
		seen[key] = true
		if _, target := targets[name]; target {
			var code [32]byte
			if size < int64(len(code)) || mode&0170000 != 0100000 || mode&0111 == 0 || links != 1 {
				return ErrMetadata
			}
			if _, err := io.ReadFull(raw, code[:]); err != nil || !thinMachO(code[:], architecture) {
				return ErrMetadata
			}
			targets[name] = true
			size -= int64(len(code))
		}
		if _, err := io.CopyN(io.Discard, raw, size); err != nil || raw.N <= 0 {
			return ErrMetadata
		}
	}
	return ErrMetadata
}

func thinMachO(data []byte, architecture string) bool {
	if len(data) != 32 || binary.LittleEndian.Uint32(data[:4]) != 0xfeedfacf || binary.LittleEndian.Uint32(data[12:16]) != 2 {
		return false
	}
	cpu := binary.LittleEndian.Uint32(data[4:8])
	return architecture == "amd64" && cpu == 0x01000007 || architecture == "arm64" && cpu == 0x0100000c
}
