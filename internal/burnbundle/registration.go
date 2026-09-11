package burnbundle

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const burnNamespace = "http://wixtoolset.org/schemas/v4/2008/Burn"

// Registration is embedded metadata, not execution authority. Architecture and
// registry view describe the bootstrapper; Scope is exactly machine or user.
type Registration struct {
	BundleCode   string
	Architecture string
	Version      string
	Scope        string
	RegistryView string
}

// ReadRegistration reads the bounded UX manifest into memory through the Windows
// cabinet decoder, then binds its registration to the PE header. It never writes
// members to disk, launches a bundle or changes native registration. Production
// execution integration must invoke it inside the bounded preflight subprocess.
func ReadRegistration(ctx context.Context, reader io.ReaderAt, size int64) (Registration, error) {
	var empty Registration
	if ctx == nil || ctx.Err() != nil {
		return empty, ErrFormat
	}
	layout, err := Inspect(reader, size)
	if err != nil {
		return empty, ErrFormat
	}
	cabinet := io.NewSectionReader(reader, layout.UXOffset, layout.UXSize)
	index, err := indexCabinet(ctx, cabinet, layout.UXSize)
	if err != nil {
		return empty, ErrFormat
	}
	manifest, err := decodeCabinet(ctx, cabinet, layout.UXSize, index)
	defer clear(manifest)
	if err != nil || ctx.Err() != nil {
		return empty, ErrFormat
	}
	registration, err := parseRegistration(layout, manifest)
	if err != nil || ctx.Err() != nil {
		return empty, ErrFormat
	}
	return registration, nil
}

func parseRegistration(layout Layout, data []byte) (Registration, error) {
	var empty Registration
	if len(data) == 0 || int64(len(data)) > maxManifestSize || !utf8.Valid(data) || layout.BundleCode == "" || !slices.Contains([]string{"386", "amd64", "arm64"}, layout.Architecture) {
		return empty, ErrFormat
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var stack []string
	var root, registration, arp map[string]string
	seenRoot, closedRoot, declaration := false, false, false
	for nodes := 0; ; nodes++ {
		if nodes > 32768 {
			return empty, ErrFormat
		}
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return empty, ErrFormat
		}
		switch value := token.(type) {
		case xml.StartElement:
			if closedRoot || len(stack) >= 32 || value.Name.Space != burnNamespace || len(value.Attr) > 64 {
				return empty, ErrFormat
			}
			attributes := make(map[string]string, len(value.Attr))
			for _, attribute := range value.Attr {
				if attribute.Name.Space != "" || len(attribute.Value) > 4096 {
					return empty, ErrFormat
				}
				name := attribute.Name.Local
				if _, exists := attributes[name]; exists {
					return empty, ErrFormat
				}
				if name == "xmlns" && (len(stack) != 0 || attribute.Value != burnNamespace) {
					return empty, ErrFormat
				}
				attributes[name] = attribute.Value
			}
			if len(stack) == 0 {
				if seenRoot || value.Name.Local != "BurnManifest" {
					return empty, ErrFormat
				}
				root, seenRoot = attributes, true
			}
			if value.Name.Local == "Registration" {
				if len(stack) != 1 || registration != nil {
					return empty, ErrFormat
				}
				registration = attributes
			}
			if value.Name.Local == "Arp" {
				if len(stack) != 2 || stack[1] != "Registration" || arp != nil {
					return empty, ErrFormat
				}
				arp = attributes
			}
			if len(stack) > 2 && stack[2] == "Arp" {
				return empty, ErrFormat
			}
			stack = append(stack, value.Name.Local)
		case xml.EndElement:
			if len(stack) == 0 || value.Name.Space != burnNamespace || value.Name.Local != stack[len(stack)-1] {
				return empty, ErrFormat
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				closedRoot = true
			}
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(value)) != 0 {
				return empty, ErrFormat
			}
		case xml.ProcInst:
			if value.Target != "xml" || seenRoot || declaration {
				return empty, ErrFormat
			}
			declaration = true
		case xml.Directive:
			return empty, ErrFormat
		}
	}
	if !closedRoot || len(stack) != 0 || registration == nil || arp == nil || !attributeSet(root, "xmlns", "EngineVersion", "ProtocolVersion", "Win64") || root["ProtocolVersion"] != "1" || !engineVersion(root["EngineVersion"]) {
		return empty, ErrFormat
	}
	view, win64 := "64", "yes"
	if layout.Architecture == "386" {
		view, win64 = "32", "no"
	}
	if root["Win64"] != win64 {
		return empty, ErrFormat
	}
	code, scope := "", ""
	if _, old := registration["Id"]; old {
		if !attributeSet(registration, "Id", "PerMachine", "ExecutableName", "Tag", "Version", "ProviderKey") {
			return empty, ErrFormat
		}
		code = registration["Id"]
		scope = map[string]string{"yes": "machine", "no": "user"}[registration["PerMachine"]]
	} else {
		if !attributeSet(registration, "Code", "Scope", "BundleId", "ExecutableName", "Tag", "Version", "ProviderKey", "PrimaryUpgradeCode") {
			return empty, ErrFormat
		}
		code = registration["Code"]
		scope = map[string]string{"perMachine": "machine", "perUser": "user"}[registration["Scope"]]
	}
	// Flexible per-user/per-machine scope cannot prove an exact registry hive.
	if scope == "" || code != layout.BundleCode || !registrationText(registration["Version"], 128) || arp["DisplayVersion"] != registration["Version"] {
		return empty, ErrFormat
	}
	if !attributeSet(arp, "DisplayName", "DisplayVersion", "InProgressDisplayName", "Publisher", "HelpLink", "HelpTelephone", "AboutUrl", "UpdateUrl", "ParentDisplayName", "DisableModify", "DisableRemove") {
		return empty, ErrFormat
	}
	return Registration{BundleCode: code, Architecture: layout.Architecture, Version: registration["Version"], Scope: scope, RegistryView: view}, nil
}

func attributeSet(attributes map[string]string, allowed ...string) bool {
	for key := range attributes {
		if !slices.Contains(allowed, key) {
			return false
		}
	}
	return true
}

func engineVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for i, part := range parts {
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(number, 10) != part || i == 0 && number < 4 {
			return false
		}
	}
	return true
}

func registrationText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
