//go:build windows && openuem_msi_test

package windowssoftware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/open-uem/openuem-agent/internal/windowstest"
)

func TestNativeWindowsSoftwareOwnedMSIReadOnlyCompatibility(t *testing.T) {
	msi := windowstest.NewMSI(t, t.TempDir())
	r := Rule{Kind: "msi-product", ProductCode: msi.ProductCode, Version: msi.Version}
	if readMSIMetadata(msi.Path, "amd64", r) != nil {
		t.Fatal("exact read-only MSI metadata denied")
	}
	if readMSIMetadata(msi.Path, "arm64", r) == nil {
		t.Fatal("foreign MSI architecture admitted")
	}
	wrong := r
	wrong.Version = "1.2.30"
	if readMSIMetadata(msi.Path, "amd64", wrong) == nil {
		t.Fatal("different MSI version admitted")
	}
	wrong = testRule()
	if readMSIMetadata(msi.Path, "amd64", wrong) == nil {
		t.Fatal("different MSI product admitted")
	}
	f := newStageFixture(t)
	content, err := os.ReadFile(msi.Path)
	if err != nil {
		t.Fatal(err)
	}
	f.content = content
	hash := sha256.Sum256(content)
	f.artifact.SHA256 = hex.EncodeToString(hash[:])
	f.artifact.Format = "msi"
	f.artifact.URL = strings.Replace(f.artifact.URL, "/fixture.exe?", "/fixture.msi?", 1)
	stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	plan := preflightPlan()
	plan.Artifact = f.artifact
	plan.Detection.ProductCode = msi.ProductCode
	if CheckInstaller(t.Context(), plan, stage) != nil {
		t.Fatal("retained MSI stage/helper metadata denied")
	}
	plan.Detection.Version = "1.2.30"
	if CheckInstaller(t.Context(), plan, stage) == nil {
		t.Fatal("staged MSI substituted a different version")
	}
	if o, err := Observe(t.Context(), r); err != nil || o.State != Absent {
		t.Fatal("read-only MSI preflight installed or advertised a product", o, err)
	}
}
