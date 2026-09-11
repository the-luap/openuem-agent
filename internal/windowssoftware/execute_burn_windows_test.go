//go:build openuem_burn_test && openuem_msi_test

package windowssoftware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/commands/deploy"
	"github.com/open-uem/openuem-agent/internal/windowstest"
	"golang.org/x/sys/windows"
)

func ownedBurnExecution(t *testing.T, bundle windowstest.Burn) (enrollment.SoftwarePlan, *stageFixture, installerOperations) {
	t.Helper()
	if os.Getenv("OPENUEM_WINDOWS_BURN_FIXTURE") != "1" {
		t.Fatal("owned synthetic Burn execution requires explicit fixture opt-in")
	}
	f := newStageFixture(t)
	content, err := os.ReadFile(bundle.Path)
	if err != nil {
		t.Fatal(err)
	}
	f.content = content
	hash := sha256.Sum256(content)
	f.artifact.SHA256 = hex.EncodeToString(hash[:])
	plan := burnPreflightPlan()
	plan.Artifact, plan.Architecture = f.artifact, bundle.Architecture
	plan.Detection.UninstallKey, plan.Detection.Version = bundle.BundleCode, bundle.Version
	ops := nativeInstallerOperations()
	// This tagged entry point runs the same production builder/runner and only
	// exposes native errors for our generated fixture. No private output is read.
	ops.run = func(ctx context.Context, plan enrollment.SoftwarePlan, path string) (installerProcess, error) {
		result, err := deploy.RunOwnedBurnProcessFixture(ctx, plan, path)
		if err != nil {
			t.Logf("owned Burn process diagnostic: %v", err)
		}
		return installerProcess{Started: result.Started, ExitCode: result.ExitCode}, err
	}
	// Only the test seam accepts this generated unsigned bundle. Production
	// staging always requires actual Authenticode before retaining a candidate.
	ops.stage = func(ctx context.Context, p enrollment.SoftwarePlan, root string) (installerStage, error) {
		stage, err := stageArtifact(ctx, p.Artifact, root, f.client, func(context.Context, string, string) error { return nil })
		if stage == nil {
			return nil, err
		}
		return ownedBurnStage{StagedArtifact: stage, t: t}, err
	}
	return plan, f, ops
}

type ownedBurnStage struct {
	*StagedArtifact
	t *testing.T
}

func (s ownedBurnStage) Close() error {
	err := s.StagedArtifact.close(func(path string) error {
		err := os.Remove(path)
		if err != nil {
			var code syscall.Errno
			_ = errors.As(err, &code)
			s.t.Logf("owned Burn stage removal diagnostic: directory=%t windows_error=%d", path == s.directory, uint32(code))
		}
		return err
	})
	if err != nil {
		s.t.Error("owned Burn stage cleanup failed", err)
	}
	return err
}

func TestNativeWindowsSoftwareOwnedBurnInstallAndRemove(t *testing.T) {
	bundle, msi := windowstest.NewMSIBurn(t)
	plan, f, ops := ownedBurnExecution(t, bundle)
	remove := plan
	remove.Operation, remove.Arguments = "remove", []string{"/uninstall", "/quiet", "/norestart"}
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
		observed, observeErr := Observe(ctx, msiRule)
		t.Logf("owned MSI observation after incomplete Burn process: state=%s version=%s error=%v", observed.State, observed.Version, observeErr)
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

func TestNativeWindowsSoftwareOwnedBurnJoinsProcesses(t *testing.T) {
	for _, mode := range []string{"cancelled", "unfinished-child"} {
		t.Run(mode, func(t *testing.T) {
			fixture := windowstest.NewProcessBurn(t)
			plan, f, ops := ownedBurnExecution(t, fixture.Burn)
			remove := plan
			remove.Operation, remove.Arguments = "remove", []string{"/uninstall", "/quiet", "/norestart"}
			// Burn can leave its own cache/registration after interrupted apply.
			// Always remove only this uniquely generated bundle on the owned runner.
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				result, err := ops.run(ctx, remove, fixture.Path)
				if err != nil || result.ExitCode == nil || *result.ExitCode != 0 {
					t.Error("owned process bundle cleanup failed", result, err)
				}
				rule := Rule{Kind: "uninstall-key", UninstallKey: fixture.BundleCode, RegistryView: "64", Version: fixture.Version}
				if after, err := Observe(ctx, rule); err != nil || after.State != Absent {
					t.Error("owned process bundle cleanup retained registration", after, err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			done := make(chan enrollment.SoftwareOutcome, 1)
			go func() { done <- executeInstaller(ctx, plan, f.root, func() error { return nil }, ops) }()
			// Join the runner on every failure before attempting bundle cleanup.
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("owned Burn runner did not join during cleanup")
				}
			}()
			handles := openOwnedBurnProcesses(t, fixture)
			if mode == "cancelled" {
				cancel()
			} else if err := os.WriteFile(fixture.Release, []byte("release"), 0600); err != nil {
				t.Fatal(err)
			}
			select {
			case out := <-done:
				// Restore the value for the unconditional join above.
				done <- out
				if !out.ValidFor(plan) || out.State != "uncertain" || out.Execution != "started" || out.ExitCode != nil || out.After.State != Unknown {
					t.Fatal("interrupted or unfinished Burn became a completed installation", out)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("owned Burn exceeded bounded process shutdown")
			}
			for _, handle := range handles {
				if state, err := windows.WaitForSingleObject(handle, 2000); err != nil || state != windows.WAIT_OBJECT_0 {
					t.Fatal("owned Burn payload or child survived the process boundary", state, err)
				}
			}
			assertStageEmpty(t, f.root)
		})
	}
}

func openOwnedBurnProcesses(t *testing.T, fixture windowstest.BurnProcesses) []windows.Handle {
	t.Helper()
	want, err := os.ReadFile(fixture.Payload)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(want)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(fixture.PIDs)
		var pids []uint32
		if err == nil && json.Unmarshal(data, &pids) == nil && len(pids) == 2 && pids[0] != pids[1] {
			var handles []windows.Handle
			for _, pid := range pids {
				handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, pid)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = windows.CloseHandle(handle) })
				name := make([]uint16, 32768)
				length := uint32(len(name))
				if err = windows.QueryFullProcessImageName(handle, 0, &name[0], &length); err != nil {
					t.Fatal(err)
				}
				image, err := os.ReadFile(windows.UTF16ToString(name[:length]))
				if err != nil || sha256.Sum256(image) != wantHash {
					t.Fatal("published process did not run the uniquely generated owned payload", err)
				}
				// Retain verified handles, never terminate a PID rediscovered later.
				t.Cleanup(func() {
					if state, _ := windows.WaitForSingleObject(handle, 0); state == uint32(windows.WAIT_TIMEOUT) {
						_ = windows.TerminateProcess(handle, 95)
						_, _ = windows.WaitForSingleObject(handle, 2000)
					}
				})
				handles = append(handles, handle)
			}
			return handles
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owned Burn payload did not publish its process identities")
	return nil
}
