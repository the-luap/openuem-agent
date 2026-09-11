package windowssoftware

import (
	"os"
	"runtime"
	"testing"
)

func TestNativeWindowsSoftwareHostAndPECompatibility(t *testing.T) {
	plan := preflightPlan()
	plan.Architecture = runtime.GOARCH
	if err := CheckHost(t.Context(), plan); err != nil {
		t.Fatal("native host preflight", err)
	}
	plan.MinimumOS = "10.0.99999"
	if CheckHost(t.Context(), plan) == nil {
		t.Fatal("future OS minimum admitted")
	}
	plan.MinimumOS = "10.0.1000"
	if runtime.GOARCH == "amd64" {
		plan.Architecture = "arm64"
	} else {
		plan.Architecture = "amd64"
	}
	if CheckHost(t.Context(), plan) == nil {
		t.Fatal("foreign native architecture admitted")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if readPEArchitecture(executable, machineForArchitecture(runtime.GOARCH)) != nil {
		t.Fatal("native test PE rejected")
	}
	if readPEArchitecture(executable, machineForArchitecture(plan.Architecture)) == nil {
		t.Fatal("foreign PE architecture admitted")
	}
	path := t.TempDir() + string(os.PathSeparator) + "invalid.exe"
	if os.WriteFile(path, []byte("not a PE executable"), 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if readPEArchitecture(path, machineForArchitecture(runtime.GOARCH)) == nil {
		t.Fatal("invalid PE accepted")
	}
}
