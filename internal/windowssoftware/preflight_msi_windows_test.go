//go:build windows && openuem_msi_test

package windowssoftware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"

	"github.com/open-uem/openuem-agent/internal/windowstest"
)

func TestNativeWindowsSoftwareOwnedMSIReadOnlyCompatibility(t *testing.T) {
	msi := windowstest.NewMSI(t, t.TempDir())
	r := Rule{Kind: "msi-product", ProductCode: msi.ProductCode, Version: msi.Version}
	if readMSIMetadata(msi.Path, runtime.GOARCH, r) != nil {
		t.Fatal("exact read-only MSI metadata denied")
	}
	if readMSIMetadata(msi.Path, map[string]string{"amd64": "arm64", "arm64": "amd64"}[runtime.GOARCH], r) == nil {
		t.Fatal("foreign MSI architecture admitted")
	}
	wrong := r
	wrong.Version = "1.2.30"
	if readMSIMetadata(msi.Path, runtime.GOARCH, wrong) == nil {
		t.Fatal("different MSI version admitted")
	}
	wrong = testRule()
	if readMSIMetadata(msi.Path, runtime.GOARCH, wrong) == nil {
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
	plan.Architecture = runtime.GOARCH
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

func TestNativeWindowsSoftwareOwnedMSIExecutorInstallAndRemove(t *testing.T) {
	if os.Getenv("OPENUEM_WINDOWS_MSI_FIXTURE") != "1" {
		t.Fatal("owned synthetic MSI execution requires explicit fixture opt-in")
	}
	msi := windowstest.NewMSI(t, t.TempDir())
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
	plan := preflightPlan()
	plan.Architecture = runtime.GOARCH
	plan.Artifact, plan.MSIProperties, plan.Detection.ProductCode = f.artifact, msi.Properties, msi.ProductCode
	remove := plan
	remove.Operation, remove.Artifact, remove.MSIProperties = "remove", enrollment.SoftwareArtifact{}, nil
	ops := nativeInstallerOperations()
	removed := false
	t.Cleanup(func() {
		if removed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		result, err := ops.run(ctx, remove, "")
		if err != nil || result.ExitCode == nil || *result.ExitCode != 0 && *result.ExitCode != 1605 {
			t.Error("owned executor product cleanup failed", err)
		}
	})
	// Only this test seam accepts the generated unsigned MSI. Production Execute
	// always uses Stage with actual Authenticode; it has no verifier override.
	ops.stage = func(ctx context.Context, p enrollment.SoftwarePlan, root string) (installerStage, error) {
		return stageArtifact(ctx, p.Artifact, root, f.client, func(context.Context, string, string) error { return nil })
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	live := func() error { return nil }
	out := executeInstaller(ctx, plan, f.root, live, ops)
	if !out.ValidFor(plan) || out.State != "observed" || out.Execution != "started" || out.Before.State != Absent || !out.After.Matches(plan.Detection) {
		t.Fatal("native staged MSI execution lacked exact observed evidence", out)
	}
	assertStageEmpty(t, f.root)
	before := f.requests.Load()
	out = executeInstaller(ctx, plan, f.root, live, ops)
	if !out.ValidFor(plan) || out.State != "observed" || out.Execution != "not_started" || f.requests.Load() != before {
		t.Fatal("already observed MSI was downloaded or executed again", out)
	}
	wrong := remove
	wrong.Detection.Version = "1.2.30"
	out = executeInstaller(ctx, wrong, f.root, live, ops)
	if !out.ValidFor(wrong) || out.State != "not_started" || out.Error != "version_conflict" {
		t.Fatal("different installed MSI version became removable", out)
	}
	out = executeInstaller(ctx, remove, f.root, live, ops)
	if !out.ValidFor(remove) || out.State != "observed" || out.Execution != "started" || out.After.State != Absent {
		t.Fatal("native MSI removal lacked exact absence evidence", out)
	}
	removed = true
	if f.requests.Load() != before {
		t.Fatal("native MSI removal fetched an artifact")
	}
}
