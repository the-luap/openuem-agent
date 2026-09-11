//go:build openuem_burn_test && openuem_msi_test

package windowstest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// NewMSIBurn builds an independently identified machine bundle containing only
// our generated registry-only MSI. The caller owns any installation and cleanup.
func NewMSIBurn(t *testing.T) (Burn, MSI) {
	t.Helper()
	wix := os.Getenv("OPENUEM_BURN_WIX")
	if !filepath.IsAbs(wix) {
		t.Fatal("owned Burn fixture requires the isolated pinned WiX tool")
	}
	root := t.TempDir()
	msi := NewMSI(t, root)
	runBurnTool(t, root, nil, wix, "extension", "add", "WixToolset.Bal.wixext/4.0.6")
	source := `<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" xmlns:bal="http://wixtoolset.org/schemas/v4/wxs/bal">
  <Bundle Name="OpenUEM owned Burn MSI fixture" Manufacturer="OpenUEM test" Version="1.2.3.4" UpgradeCode="` + uuid.NewString() + `">
    <BootstrapperApplication><bal:WixStandardBootstrapperApplication LicenseUrl="" Theme="hyperlinkLicense" /></BootstrapperApplication>
    <Chain><MsiPackage SourceFile="owned fixture.msi" /></Chain>
  </Bundle>
</Wix>`
	if err := os.WriteFile(filepath.Join(root, "bundle.wxs"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return buildBurnFixture(t, root, wix, "amd64", "machine", "yes"), msi
}
