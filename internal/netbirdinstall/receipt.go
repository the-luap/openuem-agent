package netbirdinstall

import (
	"io"
	"strconv"
	"strings"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

// verifyNativeReceipt accepts the bounded native XML plist, rejecting duplicate
// keys and ambiguous structure before matching the exact receipt and root volume.
func verifyNativeReceipt(reader io.Reader, descriptor packageapi.Package) error {
	version, err := nativeReceiptVersion(reader)
	if err != nil || descriptor.PackageID != "io.netbird.client" || descriptor.Version != version {
		return ErrInstallation
	}
	return nil
}

func nativeReceiptVersion(reader io.Reader) (string, error) {
	values, err := nativePlist(reader, 32<<10)
	if err != nil {
		return "", ErrInstallation
	}
	// pkgutil receipt output is a flat dictionary, not arbitrary plist data.
	for _, value := range values {
		if len(value.children) != 0 {
			return "", ErrInstallation
		}
	}
	stringValue := func(key, want string) bool {
		value := values[key]
		return value != nil && value.name == "string" && value.text == want
	}
	if !stringValue("pkgid", "io.netbird.client") || !stringValue("volume", "/") || !stringValue("install-location", "/") && !stringValue("install-location", "") {
		return "", ErrInstallation
	}
	installed := values["install-time"]
	if installed == nil || installed.name != "integer" {
		return "", ErrInstallation
	}
	n, err := strconv.ParseInt(installed.text, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != installed.text {
		return "", ErrInstallation
	}
	version, ok := plistString(values, "pkg-version")
	shape := packageapi.Removal{Schema: packageapi.Schema, Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: version, StateDigest: strings.Repeat("0", 64)}
	if !ok || !shape.Valid() {
		return "", ErrInstallation
	}
	return version, nil
}
