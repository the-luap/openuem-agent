package windowssoftware

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment"
)

func burnPreflightPlan() enrollment.SoftwarePlan {
	p := preflightPlan()
	p.Kind, p.Artifact.Format = "windows-burn", "exe"
	p.Artifact.URL = "https://example.invalid/fixture.exe"
	p.Arguments = []string{"/quiet", "/norestart"}
	p.Detection = enrollment.SoftwareDetection{Kind: "uninstall-key", UninstallKey: testRule().ProductCode, RegistryView: "64", Version: "1.2.3.4"}
	return p
}

func TestSoftwareBurnPreflightGrammarKeepsNativeProofExplicit(t *testing.T) {
	rule := Rule{Kind: "uninstall-key", UninstallKey: testRule().ProductCode, RegistryView: "64", Version: "1.2.3.4"}
	r := preflightRequest{Architecture: "amd64", MinimumOS: "10.0.1000", Path: filepath.Join(t.TempDir(), "installer.exe"), Format: "burn", Detection: &rule}
	if !r.valid() || !burnPreflightPlan().Valid() {
		t.Fatal("explicit Burn preflight rejected")
	}
	wire, _ := json.Marshal(r)
	var decoded preflightRequest
	if !decodeMessage(wire, &decoded) || !decoded.valid() {
		t.Fatal("Burn helper grammar changed")
	}
	for _, change := range []func(*preflightRequest){
		func(r *preflightRequest) { r.Format = "exe" },
		func(r *preflightRequest) { r.Format = "msi" },
		func(r *preflightRequest) { r.Path = "" },
		func(r *preflightRequest) { r.Path = filepath.Join(filepath.Dir(r.Path), "installer.burn") },
		func(r *preflightRequest) { r.Path = "relative.exe" },
		func(r *preflightRequest) { r.Architecture = "386" },
		func(r *preflightRequest) { r.Detection = nil },
		func(r *preflightRequest) { r.Detection.Kind = "msi-product" },
		func(r *preflightRequest) { r.Detection.ProductCode = testRule().ProductCode },
		func(r *preflightRequest) { r.Detection.RegistryView = "32" },
		func(r *preflightRequest) { r.Detection.UninstallKey = "Owned.Generic" },
		func(r *preflightRequest) { r.Detection.UninstallKey = strings.ToLower(r.Detection.UninstallKey) },
		func(r *preflightRequest) { r.Detection.UninstallKey = "{00000000-0000-0000-0000-000000000000}" },
		func(r *preflightRequest) { r.Detection.Version = " 1.2.3.4" },
	} {
		candidate, copy := r, rule
		candidate.Detection = &copy
		change(&candidate)
		if candidate.valid() {
			t.Fatal("ambiguous Burn preflight accepted")
		}
	}
	// Generic EXE inspection cannot carry Burn expectations, even for a GUID.
	r.Format, r.Detection = "exe", nil
	if !r.valid() {
		t.Fatal("existing generic EXE grammar changed")
	}
}
