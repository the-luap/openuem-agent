//go:build openuem_burn_test

package windowstest

import (
	"context"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type Burn struct {
	Path, BundleCode, Version, Architecture, Scope, RegistryView string
}

// NewBurn builds and independently extracts an owned fixture using pinned WiX.
// Neither the generated bootstrapper nor its inert payload is ever executed.
func NewBurn(t *testing.T, architecture, scope string) Burn {
	t.Helper()
	wix := os.Getenv("OPENUEM_BURN_WIX")
	wixArch := map[string]string{"386": "x86", "amd64": "x64", "arm64": "arm64"}[architecture]
	if !filepath.IsAbs(wix) || wixArch == "" || scope != "machine" && scope != "user" {
		t.Fatal("owned Burn fixture requires the isolated pinned WiX tool and an explicit target")
	}
	root := t.TempDir()
	runBurnTool(t, root, nil, wix, "extension", "add", "WixToolset.Bal.wixext/4.0.6")
	if err := os.WriteFile(filepath.Join(root, "payload.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runBurnTool(t, root, []string{"GOOS=windows", "GOARCH=" + architecture, "CGO_ENABLED=0"}, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", "payload.exe", "payload.go")
	perMachine := map[string]string{"machine": "yes", "user": "no"}[scope]
	source := `<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" xmlns:bal="http://wixtoolset.org/schemas/v4/wxs/bal">
  <Bundle Name="OpenUEM inert format fixture" Manufacturer="OpenUEM test" Version="1.2.3.4" UpgradeCode="{BDC2888B-B6A9-4975-949C-5176D433D859}">
    <BootstrapperApplication><bal:WixStandardBootstrapperApplication LicenseUrl="" Theme="hyperlinkLicense" /></BootstrapperApplication>
    <Chain><ExePackage SourceFile="payload.exe" PerMachine="` + perMachine + `" Permanent="yes" DetectCondition="0" /></Chain>
  </Bundle>
</Wix>`
	if err := os.WriteFile(filepath.Join(root, "bundle.wxs"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return buildBurnFixture(t, root, wix, architecture, scope, perMachine)
}

func buildBurnFixture(t *testing.T, root, wix, architecture, scope, perMachine string) Burn {
	t.Helper()
	bundle := filepath.Join(root, "bundle.exe")
	runBurnTool(t, root, nil, wix, "build", "bundle.wxs", "-arch", map[string]string{"386": "x86", "amd64": "x64", "arm64": "arm64"}[architecture], "-ext", "WixToolset.Bal.wixext/4.0.6", "-o", bundle)
	ux := filepath.Join(root, "ux")
	runBurnTool(t, root, nil, wix, "burn", "extract", bundle, "-outba", ux, "-intermediateFolder", root)
	manifest, err := os.ReadFile(filepath.Join(ux, "manifest.xml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		XMLName      xml.Name `xml:"BurnManifest"`
		Win64        string   `xml:"Win64,attr"`
		Registration struct {
			ID         string `xml:"Id,attr"` // WiX 4 uses Id; newer authoring uses Code.
			Version    string `xml:"Version,attr"`
			PerMachine string `xml:"PerMachine,attr"`
		} `xml:"Registration"`
	}
	win64, view := "yes", "64"
	if architecture == "386" {
		win64, view = "no", "32"
	}
	if err := xml.Unmarshal(manifest, &document); err != nil || document.Registration.ID == "" || document.Registration.Version != "1.2.3.4" || document.Registration.PerMachine != perMachine || document.Win64 != win64 {
		t.Fatal("independently extracted fixture does not match authored target", err)
	}
	return Burn{Path: bundle, BundleCode: document.Registration.ID, Version: document.Registration.Version, Architecture: architecture, Scope: scope, RegistryView: view}
}

func runBurnTool(t *testing.T, dir string, overrides []string, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Dir, command.Env = dir, os.Environ()
	for _, override := range overrides {
		key := strings.SplitN(override, "=", 2)[0]
		filtered := command.Env[:0]
		for _, value := range command.Env {
			if !strings.EqualFold(strings.SplitN(value, "=", 2)[0], key) {
				filtered = append(filtered, value)
			}
		}
		command.Env = append(filtered, override)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("owned fixture tool %s failed: %v\n%s", filepath.Base(name), err, output)
	}
}
