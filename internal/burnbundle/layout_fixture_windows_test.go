//go:build openuem_burn_test

package burnbundle

import (
	"context"
	"debug/pe"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This opt-in CI fixture invokes only the Go and pinned WiX build/extract tools.
// It never invokes a generated bootstrapper, payload or installer operation.
func TestOwnedWiXBundleLayout(t *testing.T) {
	wix := os.Getenv("OPENUEM_BURN_WIX")
	if wix == "" || !filepath.IsAbs(wix) {
		t.Fatal("an absolute path to the isolated pinned WiX tool is required")
	}
	root := t.TempDir()
	runFixtureTool(t, root, nil, wix, "extension", "add", "WixToolset.Bal.wixext/4.0.6")
	for _, target := range []struct{ wixArch, goArch string }{{"x86", "386"}, {"x64", "amd64"}, {"arm64", "arm64"}} {
		t.Run(target.goArch, func(t *testing.T) {
			dir := filepath.Join(root, target.goArch)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "payload.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			runFixtureTool(t, dir, []string{"GOOS=windows", "GOARCH=" + target.goArch, "CGO_ENABLED=0"}, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", "payload.exe", "payload.go")
			const source = `<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" xmlns:bal="http://wixtoolset.org/schemas/v4/wxs/bal">
  <Bundle Name="OpenUEM inert format fixture" Manufacturer="OpenUEM test" Version="1.2.3.4" UpgradeCode="{BDC2888B-B6A9-4975-949C-5176D433D859}">
    <BootstrapperApplication><bal:WixStandardBootstrapperApplication LicenseUrl="" Theme="hyperlinkLicense" /></BootstrapperApplication>
    <Chain><ExePackage SourceFile="payload.exe" PerMachine="yes" Permanent="yes" DetectCondition="0" /></Chain>
  </Bundle>
</Wix>`
			if err := os.WriteFile(filepath.Join(dir, "bundle.wxs"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			// The local extension cache belongs to root; compilation uses that directory.
			bundle := filepath.Join(dir, "bundle.exe")
			runFixtureTool(t, root, nil, wix, "build", filepath.Join(dir, "bundle.wxs"), "-bindpath", dir, "-arch", target.wixArch, "-ext", "WixToolset.Bal.wixext/4.0.6", "-o", bundle)
			file, err := os.Open(bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			layout, err := Inspect(file, info.Size())
			if err != nil {
				if parsed, parseErr := pe.NewFile(file); parseErr == nil {
					t.Logf("generated PE: machine=%#x optional=%+v", parsed.Machine, parsed.OptionalHeader)
					for _, section := range parsed.Sections {
						t.Logf("section: %+v", section.SectionHeader)
					}
				}
				t.Fatal(err)
			}
			// WiX independently extracts the generated manifest. Compare its declared
			// registration with the bundle code read from the PE section by our parser.
			ux := filepath.Join(dir, "ux")
			runFixtureTool(t, root, nil, wix, "burn", "extract", bundle, "-outba", ux, "-intermediateFolder", dir)
			manifest, err := os.ReadFile(filepath.Join(ux, "manifest.xml"))
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				XMLName      xml.Name `xml:"BurnManifest"`
				Registration struct {
					ID      string `xml:"Id,attr"` // WiX 4 uses Id; newer authoring uses Code.
					Version string `xml:"Version,attr"`
				} `xml:"Registration"`
			}
			if err := xml.Unmarshal(manifest, &document); err != nil {
				t.Fatal(err)
			}
			if layout.Architecture != target.goArch || layout.BundleCode == "" || layout.BundleCode != document.Registration.ID || document.Registration.Version != "1.2.3.4" {
				t.Fatalf("generated bundle identity mismatch: %+v / %+v", layout, document.Registration)
			}
			t.Logf("read-only generated bundle inspection: %+v", layout)
		})
	}
}

func runFixtureTool(t *testing.T, dir string, overrides []string, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = os.Environ()
	for _, override := range overrides {
		key := strings.SplitN(override, "=", 2)[0] + "="
		filtered := command.Env[:0]
		for _, value := range command.Env {
			if !strings.EqualFold(strings.SplitN(value, "=", 2)[0]+"=", key) {
				filtered = append(filtered, value)
			}
		}
		command.Env = append(filtered, override)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("owned fixture tool %s failed: %v\n%s", filepath.Base(name), err, output)
	}
}
