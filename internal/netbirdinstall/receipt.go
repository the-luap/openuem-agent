package netbirdinstall

import (
	"bytes"
	"encoding/xml"
	"io"
	"strconv"
	"strings"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

// verifyNativeReceipt accepts the bounded native XML plist, rejecting duplicate
// keys and ambiguous structure before matching the exact receipt and root volume.
func verifyNativeReceipt(reader io.Reader, descriptor packageapi.Package) error {
	data, err := io.ReadAll(io.LimitReader(reader, (32<<10)+1))
	if err != nil || len(data) > 32<<10 {
		return ErrInstallation
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var clean bytes.Buffer
	encoder := xml.NewEncoder(&clean)
	doctype, rootSeen := false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrInstallation
		}
		if directive, ok := token.(xml.Directive); ok {
			if doctype || rootSeen || strings.TrimSpace(string(directive)) != `DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"` {
				return ErrInstallation
			}
			doctype = true
			continue
		}
		if _, ok := token.(xml.StartElement); ok {
			rootSeen = true
		}
		if encoder.EncodeToken(token) != nil {
			return ErrInstallation
		}
	}
	if encoder.Flush() != nil {
		return ErrInstallation
	}
	root, err := boundedXML(bytes.NewReader(clean.Bytes()), 32<<10, false)
	if err != nil || root.name != "plist" || root.attrs["version"] != "1.0" || len(root.attrs) != 1 || len(root.children) != 1 || strings.TrimSpace(root.text) != "" {
		return ErrInstallation
	}
	dict := root.children[0]
	if dict.name != "dict" || len(dict.attrs) != 0 || len(dict.children)%2 != 0 || strings.TrimSpace(dict.text) != "" {
		return ErrInstallation
	}
	values := make(map[string]*xmlNode)
	for index := 0; index < len(dict.children); index += 2 {
		key, value := dict.children[index], dict.children[index+1]
		if key.name != "key" || key.text == "" || len(key.children) != 0 || len(key.attrs) != 0 || values[key.text] != nil || len(value.attrs) != 0 || len(value.children) != 0 {
			return ErrInstallation
		}
		values[key.text] = value
	}
	stringValue := func(key, want string) bool {
		value := values[key]
		return value != nil && value.name == "string" && value.text == want
	}
	if !stringValue("pkgid", descriptor.PackageID) || !stringValue("pkg-version", descriptor.Version) || !stringValue("volume", "/") || !stringValue("install-location", "/") && !stringValue("install-location", "") {
		return ErrInstallation
	}
	installed := values["install-time"]
	if installed == nil || installed.name != "integer" {
		return ErrInstallation
	}
	n, err := strconv.ParseInt(installed.text, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != installed.text {
		return ErrInstallation
	}
	return nil
}
