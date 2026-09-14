package netbirdinstall

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestRemovalReceiptListRequiresCompleteTypedSuccessfulNativeOutput(t *testing.T) {
	for _, kind := range []string{"empty-array", "unrelated", "present", "prefix", "suffix", "empty-output", "whitespace", "duplicate", "number", "nested", "empty-id", "multiline", "oversized-id", "oversized-list", "too-many", "doctype", "trailing", "namespace", "unknown-attribute", "tool-failure", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			data := `<plist version="1.0"><array/></plist>`
			item := ""
			switch kind {
			case "unrelated":
				item = `<string>io.owned.unrelated</string>`
			case "present":
				item = `<string>io.netbird.client</string>`
			case "prefix":
				item = `<string>io.netbird.client.other</string>`
			case "suffix":
				item = `<string>other.io.netbird.client</string>`
			case "duplicate":
				item = `<string>io.netbird.client</string><string>io.netbird.client</string>`
			case "number":
				item = `<integer>1</integer>`
			case "nested":
				item = `<array><string>io.netbird.client</string></array>`
			case "empty-id":
				item = `<string/>`
			case "multiline":
				item = "<string>io.netbird.client\n</string>"
			case "oversized-id":
				item = "<string>" + strings.Repeat("a", 1025) + "</string>"
			case "too-many":
				var b strings.Builder
				for i := 0; i < 8193; i++ {
					fmt.Fprintf(&b, "<string>io.owned.%d</string>", i)
				}
				item = b.String()
			case "namespace":
				item = `<string xmlns="urn:owned">io.netbird.client</string>`
			case "unknown-attribute":
				item = `<string key="value">io.netbird.client</string>`
			}
			if item != "" {
				data = `<plist version="1.0"><array>` + item + `</array></plist>`
			}
			switch kind {
			case "empty-output":
				data = ""
			case "whitespace":
				data = "\n"
			case "oversized-list":
				data = strings.Repeat(" ", maxRemovalReceiptList+1)
			case "doctype":
				data = `<!DOCTYPE plist SYSTEM "file:///owned-private">` + data
			case "trailing":
				data += `<plist version="1.0"><array/></plist>`
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			present, err := nativeRemovalReceiptPresent(ctx, func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
				calls++
				if path != "/usr/sbin/pkgutil" || !reflect.DeepEqual(args, []string{"--volume", "/", "--pkgs-plist"}) || limit != maxRemovalReceiptList {
					t.Fatal("receipt presence used a variable or unbounded native command")
				}
				if kind == "tool-failure" {
					return errors.New("owned private diagnostic")
				}
				if kind == "cancelled" {
					cancel()
				}
				return consume(strings.NewReader(data))
			})
			want := kind == "empty-array" || kind == "unrelated" || kind == "present" || kind == "prefix" || kind == "suffix"
			if (err == nil) != want || present != (kind == "present") || calls != 1 {
				t.Fatal("ambiguous receipt output became native absence or presence", err)
			}
			if err != nil && err != ErrRemoval {
				t.Fatal("private diagnostic escaped")
			}
		})
	}
}

func TestRemovalReceiptListSupportsBoundedLargeNativeInventory(t *testing.T) {
	var data strings.Builder
	data.WriteString(`<plist version="1.0"><array>`)
	for i := 0; i < 8192; i++ {
		fmt.Fprintf(&data, "<string>io.owned.%d</string>\n", i)
	}
	data.WriteString(`</array></plist>`)
	if present, err := removalReceiptListed(strings.NewReader(data.String()), "io.owned.8191"); err != nil || !present {
		t.Fatal("complete bounded inventory was rejected", err)
	}
}
