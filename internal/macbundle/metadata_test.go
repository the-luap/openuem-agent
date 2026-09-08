package macbundle

import (
	"bytes"
	"errors"
	"testing"
)

func TestInstalledMetadataRejectsChangedServicePolicyAndAmbiguousDocuments(t *testing.T) {
	o := Options{Version: "0.12.0", Build: 42}
	if err := ValidateMetadata(infoPlist(o), daemonPlist()); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"foreign-id", "foreign-program", "foreign-identity", "user-account", "extra-environment", "duplicate-key", "old-minimum", "invalid-version", "unknown-info", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			info, daemon := infoPlist(o), daemonPlist()
			switch scenario {
			case "foreign-id":
				info = bytes.ReplaceAll(info, []byte(BundleIdentifier), []byte("org.example.foreign"))
			case "foreign-program":
				daemon = bytes.ReplaceAll(daemon, []byte(ExecutableRelative), []byte("Contents/MacOS/another-agent"))
			case "foreign-identity":
				daemon = bytes.ReplaceAll(daemon, []byte(IdentityDirectory), []byte("/Library/AnotherIdentity"))
			case "user-account":
				daemon = bytes.ReplaceAll(daemon, []byte("<string>root</string>"), []byte("<string>nobody</string>"))
			case "extra-environment":
				daemon = bytes.Replace(daemon, []byte("</dict></plist>"), []byte("<key>EnvironmentVariables</key><dict><key>DYLD_INSERT_LIBRARIES</key><string>/tmp/foreign.dylib</string></dict></dict></plist>"), 1)
			case "duplicate-key":
				info = bytes.Replace(info, []byte("</dict></plist>"), []byte("<key>CFBundleExecutable</key><string>foreign</string></dict></plist>"), 1)
			case "old-minimum":
				info = bytes.ReplaceAll(info, []byte("<string>13.0</string>"), []byte("<string>12.0</string>"))
			case "invalid-version":
				info = bytes.ReplaceAll(info, []byte("<string>42</string>"), []byte("<string>042</string>"))
			case "unknown-info":
				info = bytes.Replace(info, []byte("</dict></plist>"), []byte("<key>Unexpected</key><true/></dict></plist>"), 1)
			case "oversize":
				info = bytes.Repeat([]byte("x"), 32<<10+1)
			}
			if err := ValidateMetadata(info, daemon); !errors.Is(err, ErrMetadata) {
				t.Fatal("changed service metadata accepted", err)
			}
		})
	}
}
