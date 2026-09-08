package macsecurity

import (
	"bytes"
	"strings"
	"testing"
)

func TestRotationPlistRejectsAmbiguousOrUnboundedKeys(t *testing.T) {
	valid := []byte(fixtureRotationPlist)
	key, err := rotationKeyFromPlist(valid)
	if err != nil || !bytes.Equal(key, []byte(fixtureNewRecoveryKey)) || cap(key) != 29 {
		t.Fatal("valid tool output rejected", err)
	}
	clear(key)
	for name, bad := range map[string]string{
		"missing":            `<plist version="1.0"><dict/></plist>`,
		"truncated":          fixtureRotationPlist[:len(fixtureRotationPlist)-1],
		"trailing":           fixtureRotationPlist + "extra",
		"second root":        fixtureRotationPlist + `<plist version="1.0"><dict/></plist>`,
		"duplicate":          strings.Replace(fixtureRotationPlist, "</dict>", `<key>RecoveryKey</key><string>`+fixtureNewRecoveryKey+`</string></dict>`, 1),
		"duplicate metadata": strings.Replace(fixtureRotationPlist, "</dict>", `<key>Change</key><false/></dict>`, 1),
		"case":               strings.Replace(fixtureRotationPlist, "RecoveryKey", "recoverykey", 1),
		"lowercase key":      strings.Replace(fixtureRotationPlist, fixtureNewRecoveryKey, strings.ToLower(fixtureRecoveryKey), 1),
		"too long":           strings.Replace(fixtureRotationPlist, fixtureNewRecoveryKey, fixtureNewRecoveryKey+"A", 1),
		"type":               strings.ReplaceAll(strings.ReplaceAll(fixtureRotationPlist, "<string>", "<data>"), "</string>", "</data>"),
		"namespace":          strings.Replace(fixtureRotationPlist, `<dict>`, `<dict xmlns="https://invalid.example.test">`, 1),
		"attribute":          strings.Replace(fixtureRotationPlist, `<key>RecoveryKey`, `<key extra="1">RecoveryKey`, 1),
		"doctype":            strings.Replace(fixtureRotationPlist, "http://www.apple.com/DTDs/PropertyList-1.0.dtd", "file:///fixture-must-not-read", 1),
		"entity":             strings.Replace(fixtureRotationPlist, fixtureNewRecoveryKey, "&external;", 1),
		"depth":              strings.Replace(fixtureRotationPlist, "</dict>", `<key>nested</key>`+strings.Repeat("<array>", 17)+strings.Repeat("</array>", 17)+"</dict>", 1),
		"size":               fixtureRotationPlist + strings.Repeat(" ", maxRotationOutput),
		"array limit":        strings.Replace(fixtureRotationPlist, "</dict>", `<key>nested</key><array>`+strings.Repeat("<true/>", 65)+"</array></dict>", 1),
		"key length":         strings.Replace(fixtureRotationPlist, "SerialNumber", strings.Repeat("x", 257), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if key, err := rotationKeyFromPlist([]byte(bad)); err == nil || key != nil {
				clear(key)
				t.Fatal("invalid result exposed a candidate")
			}
		})
	}
	// A valid-looking key nested in metadata must not substitute for the root
	// dictionary's explicit RecoveryKey entry.
	nested := `<plist version="1.0"><dict><key>metadata</key><dict><key>RecoveryKey</key><string>` + fixtureNewRecoveryKey + `</string></dict></dict></plist>`
	if key, err := rotationKeyFromPlist([]byte(nested)); err == nil || key != nil {
		t.Fatal("nested metadata selected a recovery key")
	}
}

func TestRotationPlistPermitsBoundedMetadataWithoutChangingTheKey(t *testing.T) {
	extra := `<key>Metadata</key><array><dict><key>Data</key><data>YQ==</data><key>Count</key><integer>1</integer><key>Ratio</key><real>1.0</real><key>Flag</key><false/></dict><string>fixture</string></array>`
	data := strings.Replace(fixtureRotationPlist, "</dict>", extra+"</dict>", 1)
	key, err := rotationKeyFromPlist([]byte(data))
	if err != nil || !bytes.Equal(key, []byte(fixtureNewRecoveryKey)) {
		t.Fatal("metadata changed the selected key", err)
	}
	clear(key)
}

func FuzzRotationOutputPlist(f *testing.F) {
	f.Add([]byte(fixtureRotationPlist))
	f.Add([]byte(`<plist version="1.0"><dict/></plist>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := rotationKeyFromPlist(data)
		defer clear(key)
		if err == nil && (!validRecoveryKey(key) || cap(key) != 29) {
			t.Fatal("parser returned an invalid or widened key")
		}
		if err != nil && key != nil {
			t.Fatal("failed parser retained private candidate")
		}
	})
}
