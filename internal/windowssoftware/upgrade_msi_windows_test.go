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
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestNativeWindowsSoftwareOwnedMSIMajorUpgrade(t *testing.T) {
	if os.Getenv("OPENUEM_WINDOWS_MSI_FIXTURE") != "1" {
		t.Fatal("owned major upgrade requires explicit fixture opt-in")
	}
	first := windowstest.NewMSI(t, t.TempDir())
	second := windowstest.NewMSIMajorUpgrade(t, t.TempDir(), first)
	f := newStageFixture(t)
	f.artifact.Format = "msi"
	f.artifact.URL = strings.Replace(f.artifact.URL, "/fixture.exe?", "/fixture.msi?", 1)
	ops := nativeInstallerOperations()
	// Only generated, unsigned test bytes use this seam. Native trust and process
	// boundaries otherwise match the production executor.
	ops.stage = func(ctx context.Context, plan enrollment.SoftwarePlan, root string) (installerStage, error) {
		return stageArtifact(ctx, plan.Artifact, root, f.client, func(context.Context, string, string) error { return nil })
	}
	planFor := func(msi windowstest.MSI) enrollment.SoftwarePlan {
		plan := preflightPlan()
		plan.Architecture, plan.Version = runtime.GOARCH, msi.Version
		plan.Artifact = f.artifact
		plan.MSIProperties = msi.Properties
		plan.Detection.ProductCode, plan.Detection.Version = msi.ProductCode, msi.Version
		content, err := os.ReadFile(msi.Path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		plan.Artifact.SHA256 = hex.EncodeToString(digest[:])
		return plan
	}
	removeFor := func(plan enrollment.SoftwarePlan) enrollment.SoftwarePlan {
		plan.Operation, plan.Artifact, plan.MSIProperties = "remove", enrollment.SoftwareArtifact{}, nil
		return plan
	}
	firstPlan, secondPlan := planFor(first), planFor(second)
	if !firstPlan.Valid() || !secondPlan.Valid() || firstPlan.Identifier != secondPlan.Identifier || firstPlan.Detection.ProductCode == secondPlan.Detection.ProductCode || firstPlan.Artifact.SHA256 == secondPlan.Artifact.SHA256 {
		t.Fatal("major upgrade fixture did not create distinct, exact package revisions")
	}
	t.Cleanup(func() {
		for _, plan := range []enrollment.SoftwarePlan{secondPlan, firstPlan} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			result, err := ops.run(ctx, removeFor(plan), "")
			cancel()
			if err != nil || result.ExitCode == nil || *result.ExitCode != 0 && *result.ExitCode != 1605 {
				t.Error("owned upgrade product cleanup failed", err)
			}
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	live := func() error { return nil }
	observe := func(plan enrollment.SoftwarePlan, state string) {
		t.Helper()
		o, err := Observe(ctx, Rule{Kind: "msi-product", ProductCode: plan.Detection.ProductCode, Version: plan.Detection.Version})
		if err != nil || o.State != state || state == Present && o.Version != plan.Detection.Version {
			t.Fatal("native upgrade registration differs from exact expected state", o, err)
		}
	}
	payload := func(msi windowstest.MSI, present bool) {
		t.Helper()
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, msi.RegistryPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if !present {
			if err == nil {
				key.Close()
				t.Fatal("replaced MSI left its owned registry payload behind")
			}
			if err != windows.ERROR_FILE_NOT_FOUND {
				t.Fatal("owned upgrade payload absence was not established", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		defer key.Close()
		value, kind, err := key.GetStringValue("Marker")
		if err != nil || kind != registry.SZ || value != "owned" {
			t.Fatal("installed MSI registration lacked its owned payload", err)
		}
	}
	for index, msi := range []windowstest.MSI{first, second} {
		plan := []enrollment.SoftwarePlan{firstPlan, secondPlan}[index]
		observe(plan, Absent)
		var err error
		f.content, err = os.ReadFile(msi.Path)
		if err != nil {
			t.Fatal(err)
		}
		before := f.requests.Load()
		out := executeInstaller(ctx, plan, f.root, live, ops)
		if !out.ValidFor(plan) || out.State != "observed" || out.Execution != "started" || out.Before.State != Absent || !out.After.Matches(plan.Detection) || f.requests.Load() != before+1 {
			t.Fatal("major upgrade did not preserve exact staged execution evidence", index, out)
		}
		observe(plan, Present)
		payload(msi, true)
		assertStageEmpty(t, f.root)
	}
	observe(firstPlan, Absent)
	observe(secondPlan, Present)
	payload(first, false)
	payload(second, true)
	before := f.requests.Load()
	out := executeInstaller(ctx, secondPlan, f.root, live, ops)
	if !out.ValidFor(secondPlan) || out.State != "observed" || out.Execution != "not_started" || f.requests.Load() != before {
		t.Fatal("repeating the new version downloaded or reran the upgrade", out)
	}
	oldRemoval := removeFor(firstPlan)
	out = executeInstaller(ctx, oldRemoval, f.root, live, ops)
	if !out.ValidFor(oldRemoval) || out.State != "observed" || out.Execution != "not_started" || f.requests.Load() != before {
		t.Fatal("removing the replaced revision acted on its successor", out)
	}
	observe(secondPlan, Present)
	payload(second, true)
	newRemoval := removeFor(secondPlan)
	out = executeInstaller(ctx, newRemoval, f.root, live, ops)
	if !out.ValidFor(newRemoval) || out.State != "observed" || out.Execution != "started" || out.After.State != Absent || f.requests.Load() != before {
		t.Fatal("removing the successor lacked exact absence evidence", out)
	}
	observe(firstPlan, Absent)
	observe(secondPlan, Absent)
	payload(first, false)
	payload(second, false)
	assertStageEmpty(t, f.root)
}
