//go:build openuem_burn_test && openuem_msi_test

package windowssoftware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/commands/deploy"
	"github.com/open-uem/openuem-agent/internal/windowstest"
)

func TestNativeWindowsSoftwareOwnedBurnInstallAndRemove(t *testing.T) {
	if os.Getenv("OPENUEM_WINDOWS_BURN_FIXTURE") != "1" {
		t.Fatal("owned synthetic Burn execution requires explicit fixture opt-in")
	}
	bundle, msi := windowstest.NewMSIBurn(t)
	f := newStageFixture(t)
	content, err := os.ReadFile(bundle.Path)
	if err != nil {
		t.Fatal(err)
	}
	f.content = content
	hash := sha256.Sum256(content)
	f.artifact.SHA256 = hex.EncodeToString(hash[:])
	plan := burnPreflightPlan()
	plan.Artifact = f.artifact
	plan.Detection.UninstallKey, plan.Detection.Version = bundle.BundleCode, bundle.Version
	remove := plan
	remove.Operation, remove.Arguments = "remove", []string{"/uninstall", "/quiet", "/norestart"}
	ops := nativeInstallerOperations()
	// The production client advertises no Burn capability yet. This fixture
	// alone uses the existing exact EXE process boundary after Burn preflight.
	// The production builder still explicitly rejects the new Burn kind.
	ops.run = func(ctx context.Context, p enrollment.SoftwarePlan, path string) (installerProcess, error) {
		if p.Kind != "windows-burn" {
			t.Fatal("owned Burn fixture changed the inspected plan kind")
		}
		p.Kind = "windows-exe"
		result, err := deploy.RunSoftwareProcess(ctx, p, path)
		return installerProcess{Started: result.Started, ExitCode: result.ExitCode}, err
	}
	// Only the test seam accepts this generated unsigned bundle. Production
	// staging always requires actual Authenticode before retaining a candidate.
	ops.stage = func(ctx context.Context, p enrollment.SoftwarePlan, root string) (installerStage, error) {
		return stageArtifact(ctx, p.Artifact, root, f.client, func(context.Context, string, string) error { return nil })
	}
	msiRule := Rule{Kind: "msi-product", ProductCode: msi.ProductCode, Version: msi.Version}
	if before, err := Observe(t.Context(), msiRule); err != nil || before.State != Absent {
		t.Fatal("newly generated MSI identity already exists", before, err)
	}
	removed := false
	defer func() {
		if removed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		result, err := ops.run(ctx, remove, bundle.Path)
		if err != nil || result.ExitCode == nil || *result.ExitCode != 0 {
			t.Error("owned Burn cleanup failed", result, err)
		}
		if after, err := Observe(ctx, msiRule); err != nil || after.State != Absent {
			t.Error("owned Burn cleanup retained its MSI", after, err)
		}
		bundleRule := Rule{Kind: "uninstall-key", UninstallKey: bundle.BundleCode, RegistryView: "64", Version: bundle.Version}
		if after, err := Observe(ctx, bundleRule); err != nil || after.State != Absent {
			t.Error("owned Burn cleanup retained its bundle registration", after, err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	live := func() error { return nil }
	out := executeInstaller(ctx, plan, f.root, live, ops)
	if !out.ValidFor(plan) || out.State != "observed" || out.Execution != "started" || out.Before.State != Absent || !out.After.Matches(plan.Detection) {
		t.Fatal("owned Burn installation lacks exact machine evidence", out)
	}
	if installed, err := Observe(ctx, msiRule); err != nil || !installed.Matches(msiRule) {
		t.Fatal("owned Burn did not install its registry-only MSI", installed, err)
	}
	assertStageEmpty(t, f.root)
	before := f.requests.Load()
	out = executeInstaller(ctx, plan, f.root, live, ops)
	if !out.ValidFor(plan) || out.State != "observed" || out.Execution != "not_started" || f.requests.Load() != before {
		t.Fatal("already observed Burn bundle was fetched or executed again", out)
	}
	wrong := remove
	wrong.Detection.Version = "1.2.3.40"
	out = executeInstaller(ctx, wrong, f.root, live, ops)
	if !out.ValidFor(wrong) || out.State != "not_started" || out.Error != "version_conflict" || f.requests.Load() != before {
		t.Fatal("different installed Burn version became removable", out)
	}
	out = executeInstaller(ctx, remove, f.root, live, ops)
	if !out.ValidFor(remove) || out.State != "observed" || out.Execution != "started" || out.After.State != Absent || f.requests.Load() != before+1 {
		t.Fatal("owned Burn removal lacks exact pinned-artifact and absence evidence", out)
	}
	if after, err := Observe(ctx, msiRule); err != nil || after.State != Absent {
		t.Fatal("owned Burn removal retained its MSI", after, err)
	}
	removed = true
	assertStageEmpty(t, f.root)
}
