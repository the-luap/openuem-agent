package netbirdinstall

import (
	"context"
	"io"
	"strings"
)

const maxRemovalReceiptList = 512 << 10

// An empty --pkgs=REGEXP query exits with status 1 on macOS. Use the typed
// complete list instead: an empty array is a successful native observation,
// while tool failures still cannot be interpreted as package absence.
func nativeRemovalReceiptPresent(ctx context.Context, read packageReader) (bool, error) {
	if ctx == nil || ctx.Err() != nil || read == nil {
		return false, ErrRemoval
	}
	present := false
	err := read(ctx, "/usr/sbin/pkgutil", []string{"--volume", "/", "--pkgs-plist"}, maxRemovalReceiptList, func(reader io.Reader) error {
		var err error
		present, err = removalReceiptListed(reader, "io.netbird.client")
		return err
	})
	if err != nil || ctx.Err() != nil {
		return false, ErrRemoval
	}
	return present, nil
}

func removalReceiptListed(reader io.Reader, packageID string) (bool, error) {
	value, err := nativePlistValue(reader, maxRemovalReceiptList, 32796)
	if err != nil || value.name != "array" || len(value.children) > 8192 || packageID == "" {
		return false, ErrRemoval
	}
	seen := make(map[string]bool, len(value.children))
	for _, child := range value.children {
		if child.name != "string" || child.text == "" || len(child.text) > 1024 || strings.ContainsAny(child.text, "\x00\r\n\t") || seen[child.text] {
			return false, ErrRemoval
		}
		seen[child.text] = true
	}
	return seen[packageID], nil
}
