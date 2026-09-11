//go:build openuem_burn_test

package windowssoftware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/open-uem/openuem-agent/internal/windowstest"
)

func TestNativeWindowsSoftwareOwnedBurnPreflight(t *testing.T) {
	foreign := "arm64"
	if runtime.GOARCH == foreign {
		foreign = "amd64"
	}
	for _, target := range []struct{ name, architecture, scope string }{
		{"native_machine", runtime.GOARCH, "machine"},
		{"native_user", runtime.GOARCH, "user"},
		{"foreign_machine", foreign, "machine"},
		{"x86_machine", "386", "machine"},
	} {
		t.Run(target.name, func(t *testing.T) {
			bundle := windowstest.NewBurn(t, target.architecture, target.scope)
			content, err := os.ReadFile(bundle.Path)
			if err != nil {
				t.Fatal(err)
			}
			f := newStageFixture(t)
			f.content = content
			hash := sha256.Sum256(content)
			f.artifact.SHA256 = hex.EncodeToString(hash[:])
			// Only this fixture's private seam accepts our generated unsigned EXE.
			// Production Stage always requires the actual Authenticode verifier.
			stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, func(context.Context, string, string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Close()
			plan := burnPreflightPlan()
			plan.Artifact, plan.Architecture = f.artifact, runtime.GOARCH
			plan.Detection.UninstallKey, plan.Detection.Version = bundle.BundleCode, bundle.Version
			want := target.name == "native_machine"
			if err := CheckInstaller(t.Context(), plan, stage); (err == nil) != want {
				t.Fatal("bounded retained-stage Burn preflight", target.name, err)
			}
			if want {
				for _, change := range []func(){
					func() { plan.Detection.Version = "1.2.3.40" },
					func() { plan.Detection.UninstallKey = testRule().ProductCode },
					func() { plan.Artifact.SHA256 = strings.Repeat("e", 64) },
				} {
					original := plan
					change()
					if CheckInstaller(t.Context(), plan, stage) == nil {
						t.Fatal("staged Burn substituted approved registration or digest")
					}
					plan = original
				}
				plan.Operation, plan.Arguments = "remove", []string{"/uninstall", "/quiet", "/norestart"}
				if CheckInstaller(t.Context(), plan, stage) != nil {
					t.Fatal("removal did not inspect the same pinned Burn artifact")
				}
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if CheckInstaller(ctx, plan, stage) == nil {
					t.Fatal("cancelled Burn preflight succeeded")
				}
			}
			if err := stage.Close(); err != nil || CheckInstaller(t.Context(), plan, stage) == nil {
				t.Fatal("closed Burn stage retained preflight authority", err)
			}
			assertStageEmpty(t, f.root)
			rule := Rule{Kind: "uninstall-key", UninstallKey: bundle.BundleCode, RegistryView: bundle.RegistryView, Version: bundle.Version}
			if observation, err := Observe(t.Context(), rule); err != nil || observation.State != Absent {
				t.Fatal("read-only Burn proof registered a package", observation, err)
			}
		})
	}
}
