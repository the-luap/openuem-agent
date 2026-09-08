package macsecurity

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"io"
)

// Read only the bounded XML dictionary emitted by fdesetup -outputplist. PRK
// character data stays in owned bytes rather than becoming an immutable string.
// Unknown metadata may use standard plist values; it cannot select the PRK.
func rotationKeyFromPlist(data []byte) (key []byte, err error) {
	if len(data) == 0 || len(data) > maxRotationOutput {
		return nil, ErrRotationUnavailable
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	seenDeclaration, seenDoctype := false, false
	for {
		token, tokenErr := d.Token()
		if tokenErr != nil {
			return nil, ErrRotationUnavailable
		}
		switch value := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(value)) != 0 {
				return nil, ErrRotationUnavailable
			}
		case xml.Comment:
		case xml.ProcInst:
			if seenDeclaration || seenDoctype || value.Target != "xml" {
				return nil, ErrRotationUnavailable
			}
			seenDeclaration = true
		case xml.Directive:
			if seenDoctype || !bytes.Equal(bytes.TrimSpace(value), []byte(`DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"`)) {
				return nil, ErrRotationUnavailable
			}
			seenDoctype = true
		case xml.StartElement:
			if value.Name.Space != "" || value.Name.Local != "plist" || len(value.Attr) != 1 || value.Attr[0].Name.Space != "" || value.Attr[0].Name.Local != "version" || value.Attr[0].Value != "1.0" {
				return nil, ErrRotationUnavailable
			}
			goto root
		default:
			return nil, ErrRotationUnavailable
		}
	}
root:
	defer func() {
		if err != nil {
			clear(key)
			key = nil
		}
	}()
	token, err := rotationPlistToken(d)
	start, ok := token.(xml.StartElement)
	if err != nil || !ok || !rotationPlistElement(start, "dict") {
		return nil, ErrRotationUnavailable
	}
	key, err = rotationPlistDict(d, 0, true)
	if err != nil || !validRecoveryKey(key) {
		return key, ErrRotationUnavailable
	}
	token, err = rotationPlistToken(d)
	end, ok := token.(xml.EndElement)
	if err != nil || !ok || end.Name.Space != "" || end.Name.Local != "plist" {
		return key, ErrRotationUnavailable
	}
	if _, err = rotationPlistToken(d); err != io.EOF {
		return key, ErrRotationUnavailable
	}
	return key, nil
}

func rotationPlistToken(d *xml.Decoder) (xml.Token, error) {
	for {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(value)) != 0 {
				return nil, ErrRotationUnavailable
			}
		case xml.Comment:
		default:
			return token, nil
		}
	}
}

func rotationPlistElement(start xml.StartElement, name string) bool {
	return start.Name.Space == "" && start.Name.Local == name && len(start.Attr) == 0
}

func rotationPlistText(d *xml.Decoder, start xml.StartElement, limit int) (text []byte, err error) {
	text = make([]byte, 0, limit)
	defer func() {
		if err != nil {
			clear(text)
			text = nil
		}
	}()
	for {
		token, tokenErr := d.Token()
		if tokenErr != nil {
			return text, ErrRotationUnavailable
		}
		switch value := token.(type) {
		case xml.CharData:
			if len(text)+len(value) > limit {
				return text, ErrRotationUnavailable
			}
			text = append(text, value...)
		case xml.Comment:
		case xml.EndElement:
			if value.Name != start.Name {
				return text, ErrRotationUnavailable
			}
			return text, nil
		default:
			return text, ErrRotationUnavailable
		}
	}
}

func rotationPlistDict(d *xml.Decoder, depth int, recovery bool) (key []byte, err error) {
	defer func() {
		if err != nil {
			clear(key)
			key = nil
		}
	}()
	seen := make(map[[32]byte]bool)
	for count := 0; ; count++ {
		token, tokenErr := rotationPlistToken(d)
		if tokenErr != nil {
			return key, ErrRotationUnavailable
		}
		if end, ok := token.(xml.EndElement); ok && end.Name.Space == "" && end.Name.Local == "dict" {
			return key, nil
		}
		start, ok := token.(xml.StartElement)
		if count >= 64 || !ok || !rotationPlistElement(start, "key") {
			return key, ErrRotationUnavailable
		}
		name, textErr := rotationPlistText(d, start, 256)
		if textErr != nil || len(name) == 0 {
			clear(name)
			return key, ErrRotationUnavailable
		}
		digest := sha256.Sum256(name)
		selected := recovery && bytes.Equal(name, []byte("RecoveryKey"))
		clear(name)
		if seen[digest] {
			return key, ErrRotationUnavailable
		}
		seen[digest] = true
		token, tokenErr = rotationPlistToken(d)
		start, ok = token.(xml.StartElement)
		if tokenErr != nil || !ok {
			return key, ErrRotationUnavailable
		}
		if selected {
			if !rotationPlistElement(start, "string") {
				return key, ErrRotationUnavailable
			}
			key, err = rotationPlistText(d, start, 29)
			if err != nil || !validRecoveryKey(key) {
				return key, ErrRotationUnavailable
			}
		} else if err = skipRotationPlistValue(d, start, depth+1); err != nil {
			return key, err
		}
	}
}

func skipRotationPlistValue(d *xml.Decoder, start xml.StartElement, depth int) error {
	if depth > 16 || start.Name.Space != "" || len(start.Attr) != 0 {
		return ErrRotationUnavailable
	}
	switch start.Name.Local {
	case "dict":
		_, err := rotationPlistDict(d, depth, false)
		return err
	case "array":
		for count := 0; ; count++ {
			token, err := rotationPlistToken(d)
			if err != nil {
				return ErrRotationUnavailable
			}
			if end, ok := token.(xml.EndElement); ok && end.Name == start.Name {
				return nil
			}
			child, ok := token.(xml.StartElement)
			if count >= 64 || !ok || skipRotationPlistValue(d, child, depth+1) != nil {
				return ErrRotationUnavailable
			}
		}
	case "string", "data", "date", "integer", "real", "true", "false":
		value, err := rotationPlistText(d, start, maxRotationOutput)
		defer clear(value)
		if err != nil || (start.Name.Local == "true" || start.Name.Local == "false") && len(bytes.TrimSpace(value)) != 0 {
			return ErrRotationUnavailable
		}
		return nil
	default:
		return ErrRotationUnavailable
	}
}
