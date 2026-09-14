package netbirdinstall

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// nativePlist accepts Apple's XML prologue without resolving an external DTD.
// Every dictionary, including nested launchd settings, rejects duplicate keys.
func nativePlist(reader io.Reader, limit int64) (map[string]*xmlNode, error) {
	if limit < 1 || limit > 64<<10 {
		return nil, ErrInstallation
	}
	value, err := nativePlistValue(reader, limit, 4096)
	if err != nil {
		return nil, ErrInstallation
	}
	return plistDictionary(value)
}

func nativePlistValue(reader io.Reader, limit int64, tokens int) (*xmlNode, error) {
	if reader == nil || limit < 1 || limit > 512<<10 {
		return nil, ErrInstallation
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrInstallation
	}
	defer clear(data)
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var clean bytes.Buffer
	defer func() { clear(clean.Bytes()) }()
	encoder := xml.NewEncoder(&clean)
	doctype, rootSeen := false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrInstallation
		}
		if directive, ok := token.(xml.Directive); ok {
			if doctype || rootSeen || strings.TrimSpace(string(directive)) != `DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"` {
				return nil, ErrInstallation
			}
			doctype = true
			continue
		}
		if _, ok := token.(xml.StartElement); ok {
			rootSeen = true
		}
		if encoder.EncodeToken(token) != nil {
			return nil, ErrInstallation
		}
	}
	if encoder.Flush() != nil {
		return nil, ErrInstallation
	}
	root, err := boundedXMLTokens(bytes.NewReader(clean.Bytes()), limit, false, tokens)
	if err != nil || root.name != "plist" || root.attrs["version"] != "1.0" || len(root.attrs) != 1 || len(root.children) != 1 || strings.TrimSpace(root.text) != "" || !validPlistValue(root.children[0]) {
		return nil, ErrInstallation
	}
	return root.children[0], nil
}

func plistDictionary(dict *xmlNode) (map[string]*xmlNode, error) {
	if dict == nil || dict.name != "dict" || len(dict.attrs) != 0 || len(dict.children)%2 != 0 || strings.TrimSpace(dict.text) != "" {
		return nil, ErrInstallation
	}
	values := make(map[string]*xmlNode)
	for index := 0; index < len(dict.children); index += 2 {
		key, value := dict.children[index], dict.children[index+1]
		if key.name != "key" || key.text == "" || len(key.children) != 0 || len(key.attrs) != 0 || values[key.text] != nil {
			return nil, ErrInstallation
		}
		values[key.text] = value
	}
	return values, nil
}

func validPlistValue(value *xmlNode) bool {
	if value == nil || len(value.attrs) != 0 {
		return false
	}
	switch value.name {
	case "dict":
		values, err := plistDictionary(value)
		if err != nil {
			return false
		}
		for _, child := range values {
			if !validPlistValue(child) {
				return false
			}
		}
		return true
	case "array":
		if strings.TrimSpace(value.text) != "" {
			return false
		}
		for _, child := range value.children {
			if !validPlistValue(child) {
				return false
			}
		}
		return true
	case "true", "false":
		return len(value.children) == 0 && value.text == ""
	case "string", "integer", "real", "date", "data":
		return len(value.children) == 0
	default:
		return false
	}
}

func plistString(values map[string]*xmlNode, key string) (string, bool) {
	value := values[key]
	if value == nil || value.name != "string" || len(value.attrs) != 0 || len(value.children) != 0 {
		return "", false
	}
	return value.text, true
}
