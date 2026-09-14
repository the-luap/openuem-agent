package netbirdinstall

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/stretchr/testify/require"
)

func metadataDescriptor(format string) packageapi.Package {
	p := packageapi.Package{Format: format, PackageID: "netbird", Version: "0.78.1", Architecture: "arm64"}
	if format == "rpm" {
		p.Version += "-1"
	}
	if format == "pkg" {
		p.PackageID = "io.netbird.client"
	}
	return p
}

func TestLinuxMetadataExactIdentity(t *testing.T) {
	for _, format := range []string{"deb", "rpm"} {
		p := metadataDescriptor(format)
		for _, change := range []string{"none", "name", "version", "architecture", "duplicate", "trailing", "crlf", "oversize", "native-error", "epoch", "release"} {
			t.Run(format+"/"+change, func(t *testing.T) {
				data := "netbird\n0.78.1\narm64\n"
				if format == "rpm" {
					data = "netbird\n0\n0.78.1\n1\naarch64\n"
				}
				switch change {
				case "name":
					data = strings.ReplaceAll(data, "netbird", "netbird-ui")
				case "version":
					data = strings.ReplaceAll(data, "0.78.1", "0.78.2")
				case "architecture":
					data = strings.ReplaceAll(strings.ReplaceAll(data, "arm64", "amd64"), "aarch64", "x86_64")
				case "duplicate":
					data += data
				case "trailing":
					data += "private diagnostic"
				case "crlf":
					data = strings.ReplaceAll(data, "\n", "\r\n")
				case "oversize":
					data = strings.Repeat("x", (16<<10)+1)
				case "epoch":
					data = strings.ReplaceAll(data, "0.78.1", "1:0.78.1")
				case "release":
					data = strings.ReplaceAll(data, "0.78.1", "0.78.1-2")
				}
				err := inspectLinux(t.Context(), "/private/package."+format, p, func(ctx context.Context, executable string, args []string, limit int64, consume func(io.Reader) error) error {
					require.Equal(t, int64(16<<10), limit)
					require.Equal(t, "/private/package."+format, args[len(args)-1])
					if format == "deb" {
						require.Equal(t, "/usr/bin/dpkg-deb", executable)
						require.Equal(t, []string{"--show", "--showformat=${Package}\n${Version}\n${Architecture}\n", "/private/package.deb"}, args)
					} else {
						require.Equal(t, "/usr/bin/rpm", executable)
						require.Contains(t, args, "--nomanifest")
						require.Contains(t, args, "--noplugins")
						require.NotContains(t, args, "--nosignature")
					}
					if change == "native-error" {
						return ErrMetadata
					}
					return consume(strings.NewReader(data))
				})
				if change == "none" {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, ErrMetadata)
				}
			})
		}
	}
	for _, epoch := range []string{"0", "1", "20", "", "00", "01", "-1", "x", "10000000000"} {
		p := metadataDescriptor("rpm")
		if epoch != "0" {
			p.Version = epoch + ":" + p.Version
		}
		err := inspectLinux(t.Context(), "/private/package.rpm", p, func(_ context.Context, _ string, _ []string, _ int64, consume func(io.Reader) error) error {
			return consume(strings.NewReader("netbird\n" + epoch + "\n0.78.1\n1\naarch64\n"))
		})
		if epoch == "0" || epoch == "1" || epoch == "20" {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}

const ownedDistribution = `<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<pkg-ref id="io.netbird.client"><bundle-version><bundle id="io.netbird.client"/></bundle-version></pkg-ref>
<options customize="never" require-scripts="false" hostArchitectures="x86_64,arm64"/>
<choices-outline><line choice="default"><line choice="io.netbird.client"/></line></choices-outline>
<choice id="default"/><choice id="io.netbird.client" visible="false"><pkg-ref id="io.netbird.client"/></choice>
<pkg-ref id="io.netbird.client" version="0.78.1">#netbird_arm64.pkg</pkg-ref>
<product id="io.netbird.client" version="0.78.1"/>
</installer-gui-script>`

func TestPackageXMLAndDistributionRejectAmbiguity(t *testing.T) {
	for _, change := range []string{"none", "duplicate-attr", "duplicate-product", "duplicate-options", "duplicate-reference", "foreign-id", "version", "architecture", "script", "namespace", "doctype", "two-roots", "trailing", "overflow", "deep", "path", "url", "wildcard"} {
		t.Run(change, func(t *testing.T) {
			data := ownedDistribution
			switch change {
			case "duplicate-attr":
				data = strings.Replace(data, `version="0.78.1"`, `version="0.78.1" version="0.78.1"`, 1)
			case "duplicate-product":
				data = strings.Replace(data, "</installer-gui-script>", `<product id="io.netbird.client" version="0.78.1"/></installer-gui-script>`, 1)
			case "duplicate-options":
				data = strings.Replace(data, "</installer-gui-script>", `<options require-scripts="false" hostArchitectures="arm64"/></installer-gui-script>`, 1)
			case "duplicate-reference":
				data = strings.Replace(data, "</installer-gui-script>", `<pkg-ref id="io.netbird.client" version="0.78.1">#netbird_arm64.pkg</pkg-ref></installer-gui-script>`, 1)
			case "foreign-id":
				data = strings.Replace(data, "io.netbird.client", "foreign.package", 1)
			case "version":
				data = strings.Replace(data, "0.78.1", "0.78.2", 1)
			case "architecture":
				data = strings.ReplaceAll(data, "x86_64,arm64", "x86_64")
			case "script":
				data = strings.Replace(data, "</installer-gui-script>", "<script>untrusted()</script></installer-gui-script>", 1)
			case "namespace":
				data = strings.Replace(data, "minSpecVersion", `xmlns="urn:owned" minSpecVersion`, 1)
			case "doctype":
				data = `<!DOCTYPE owned [<!ENTITY x SYSTEM "file:///private">]>` + data
			case "two-roots":
				data += data
			case "trailing":
				data += "unexpected"
			case "overflow":
				data += strings.Repeat(" ", maxPackageXML)
			case "deep":
				data = strings.Repeat("<choice>", 25) + strings.Repeat("</choice>", 25)
			case "path":
				data = strings.ReplaceAll(data, "#netbird_arm64.pkg", "#netbird/../../other.pkg")
			case "url":
				data = strings.ReplaceAll(data, "#netbird_arm64.pkg", "https://example.test/netbird.pkg")
			case "wildcard":
				data = strings.ReplaceAll(data, "#netbird_arm64.pkg", "#netbird*.pkg")
			}
			root, err := packageXML(strings.NewReader(data))
			component := ""
			if err == nil {
				component, err = distributionComponent(root, metadataDescriptor("pkg"))
			}
			if change == "none" {
				require.NoError(t, err)
				require.Equal(t, "netbird_arm64.pkg", component)
			} else {
				require.Error(t, err)
			}
		})
	}
}

type ownedCPIOEntry struct {
	name        string
	mode, links int
	data        []byte
}

func ownedPayload(entries []ownedCPIOEntry, padding int) []byte {
	var raw bytes.Buffer
	for _, entry := range append(entries, ownedCPIOEntry{name: "TRAILER!!!"}) {
		fmt.Fprintf(&raw, "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o", 0, 0, entry.mode, 0, 0, entry.links, 0, 0, len(entry.name)+1, len(entry.data))
		raw.WriteString(entry.name)
		raw.WriteByte(0)
		raw.Write(entry.data)
	}
	if padding > 0 {
		raw.Write(make([]byte, padding))
	}
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	_, _ = w.Write(raw.Bytes())
	_ = w.Close()
	return compressed.Bytes()
}

func ownedCode(architecture string) []byte {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data, 0xfeedfacf)
	binary.LittleEndian.PutUint32(data[4:], map[string]uint32{"arm64": 0x0100000c, "amd64": 0x01000007}[architecture])
	binary.LittleEndian.PutUint32(data[12:], 2)
	return data
}

func ownedExecutables() []ownedCPIOEntry {
	return []ownedCPIOEntry{{"./Applications/NetBird.app/Contents/MacOS/netbird", 0100755, 1, ownedCode("arm64")}, {"./Applications/NetBird.app/Contents/MacOS/netbird-ui", 0100755, 1, ownedCode("arm64")}}
}

func TestPayloadArchitectureAndArchiveBounds(t *testing.T) {
	for _, change := range []string{"none", "wrong-client", "wrong-ui", "missing", "duplicate", "alias-duplicate", "case-alias", "unicode-alias", "linked-parent", "symlink", "hardlink", "not-executable", "short-header", "fat", "not-program", "traversal", "absolute", "padding", "truncated", "checksum", "extra-archive", "extra-bytes", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			entries, padding := ownedExecutables(), 0
			switch change {
			case "wrong-client":
				entries[0].data = ownedCode("amd64")
			case "wrong-ui":
				entries[1].data = ownedCode("amd64")
			case "missing":
				entries = entries[:1]
			case "duplicate":
				entries = append(entries, entries[0])
			case "alias-duplicate":
				e := entries[0]
				e.name = strings.TrimPrefix(e.name, "./")
				entries = append(entries, e)
			case "case-alias":
				e := entries[0]
				e.name = strings.ToUpper(e.name)
				entries = append(entries, e)
			case "unicode-alias":
				entries = append(entries, ownedCPIOEntry{name: "./Applications/NetBırd.app", mode: 0040755})
			case "linked-parent":
				entries = append(entries, ownedCPIOEntry{name: "./Applications/NetBird.app", mode: 0120755, links: 1, data: []byte("other")})
			case "symlink":
				entries[0].mode = 0120755
			case "hardlink":
				entries[0].links = 2
			case "not-executable":
				entries[0].mode = 0100644
			case "short-header":
				entries[0].data = entries[0].data[:4]
			case "fat":
				binary.BigEndian.PutUint32(entries[0].data, 0xcafebabe)
			case "not-program":
				binary.LittleEndian.PutUint32(entries[0].data[12:], 6)
			case "traversal":
				entries = append(entries, ownedCPIOEntry{name: "../outside"})
			case "absolute":
				entries = append(entries, ownedCPIOEntry{name: "/outside"})
			case "padding":
				padding = 512
			}
			data := ownedPayload(entries, padding)
			switch change {
			case "truncated":
				data = data[:len(data)-1]
			case "checksum":
				data[len(data)-8] ^= 1
			case "extra-archive":
				data = append(data, data...)
			case "extra-bytes":
				data = append(data, 1, 2, 3)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if change == "cancelled" {
				cancel()
			}
			err := inspectPayload(ctx, bytes.NewReader(data), "arm64")
			if change == "none" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrMetadata)
			}
		})
	}
}

func TestMacInspectionBindsAllThreeMembers(t *testing.T) {
	for _, change := range []string{"none", "receipt-id", "receipt-version", "receipt-duplicate", "native-error"} {
		t.Run(change, func(t *testing.T) {
			count := 0
			err := inspectMac(t.Context(), metadataDescriptor("pkg"), func(member string, _ int64, consume func(io.Reader) error) error {
				name := []string{"Distribution", "netbird_arm64.pkg/PackageInfo", "netbird_arm64.pkg/Payload"}[count]
				count++
				require.Equal(t, name, member)
				data := []byte(ownedDistribution)
				if count == 2 {
					data = []byte(`<pkg-info identifier="io.netbird.client" version="0.78.1"/>`)
					if change == "receipt-id" {
						data = bytes.ReplaceAll(data, []byte("io.netbird.client"), []byte("foreign"))
					}
					if change == "receipt-version" {
						data = bytes.ReplaceAll(data, []byte("0.78.1"), []byte("0.78.2"))
					}
					if change == "receipt-duplicate" {
						data = append(data, data...)
					}
				}
				if count == 3 {
					data = ownedPayload(ownedExecutables(), 0)
				}
				if change == "native-error" {
					return ErrMetadata
				}
				return consume(bytes.NewReader(data))
			})
			if change == "none" {
				require.NoError(t, err)
				require.Equal(t, 3, count)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestPreparedInspectionRechecksAndSerializesCleanup(t *testing.T) {
	p, client, root := packageFixture(t, "deb", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(inertPackage("deb")) })
	prepared, err := stage(t.Context(), p, root, client, noNative)
	require.NoError(t, err)
	t.Cleanup(func() { _ = prepared.Close() })
	reader := func(_ context.Context, _ string, _ []string, _ int64, consume func(io.Reader) error) error {
		return consume(strings.NewReader("netbird\n" + p.Version + "\namd64\n"))
	}
	require.NoError(t, prepared.inspect(t.Context(), p, reader))
	other := p
	other.ApprovalID = "20000000-0000-4000-8000-000000000002"
	require.ErrorIs(t, prepared.inspect(t.Context(), other, func(context.Context, string, []string, int64, func(io.Reader) error) error {
		t.Fatal("changed approval reached inspector")
		return nil
	}), ErrChanged)
	started, release, inspected, closed := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan error, 1)
	go func() {
		inspected <- prepared.inspect(t.Context(), p, func(ctx context.Context, executable string, args []string, limit int64, consume func(io.Reader) error) error {
			close(started)
			<-release
			return reader(ctx, executable, args, limit, consume)
		})
	}()
	<-started
	go func() { closed <- prepared.Close() }()
	select {
	case <-closed:
		t.Fatal("cleanup overlapped inspection")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-inspected)
	require.NoError(t, <-closed)
	require.ErrorIs(t, prepared.inspect(t.Context(), p, reader), ErrChanged)
}

func TestPreparedInspectionRejectsMutation(t *testing.T) {
	p, client, root := packageFixture(t, "deb", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(inertPackage("deb")) })
	prepared, err := stage(t.Context(), p, root, client, noNative)
	require.NoError(t, err)
	defer prepared.Close()
	err = prepared.inspect(t.Context(), p, func(_ context.Context, _ string, _ []string, _ int64, consume func(io.Reader) error) error {
		data := inertPackage("deb")
		data[len(data)-1] ^= 1
		require.NoError(t, os.WriteFile(prepared.path, data, 0600))
		return consume(strings.NewReader("netbird\n" + p.Version + "\namd64\n"))
	})
	require.ErrorIs(t, err, ErrChanged)
}

func FuzzPackageXML(f *testing.F) {
	f.Add(ownedDistribution)
	f.Add(`<pkg-info identifier="io.netbird.client" version="0.78.1"/>`)
	f.Fuzz(func(t *testing.T, data string) {
		root, err := packageXML(strings.NewReader(data))
		if err == nil {
			_, _ = distributionComponent(root, metadataDescriptor("pkg"))
		}
	})
}

func FuzzPackagePayload(f *testing.F) {
	f.Add(ownedPayload(ownedExecutables(), 0))
	f.Add([]byte("inert"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) <= 1<<20 {
			_ = inspectPayload(t.Context(), bytes.NewReader(data), "arm64")
		}
	})
}
