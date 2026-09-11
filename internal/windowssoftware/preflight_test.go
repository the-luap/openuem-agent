package windowssoftware

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
)

func preflightPlan() enrollment.SoftwarePlan {
	return enrollment.SoftwarePlan{Kind: "windows-msi", Operation: "install", Identifier: "Owned.Fixture", Version: "catalog-label", Architecture: "amd64", MinimumOS: "10.0.1000", Artifact: enrollment.SoftwareArtifact{URL: "https://example.invalid/fixture.msi", Format: "msi", SHA256: strings.Repeat("a", 64)}, Detection: enrollment.SoftwareDetection{Kind: "msi-product", ProductCode: testRule().ProductCode, Version: "1.2.3"}, SuccessCodes: []uint32{0}, RebootCodes: []uint32{3010}}
}

func TestSoftwarePreflightVersionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		minimum    string
		actual     [4]uint32
		compatible bool
	}{
		{"10.0.19045", [4]uint32{10, 0, 19045, 0}, true}, {"10.0.19045.2", [4]uint32{10, 0, 19045, 2}, true},
		{"10.0.19045.2", [4]uint32{10, 0, 19045, 1}, false}, {"10.0.19045.999", [4]uint32{10, 0, 22621, 0}, true},
		{"10.0.22621", [4]uint32{10, 0, 19045, 9999}, false}, {"10.0.19045", [4]uint32{11, 0, 99999, 0}, false},
		{"10.0.19045", [4]uint32{10, 1, 19045, 0}, false},
	} {
		if compatibleOS(tc.minimum, tc.actual) != tc.compatible {
			t.Fatal("OS compatibility boundary changed", tc)
		}
	}
	for _, invalid := range []string{"", "10.0.019045", "10.0.19045.01", "10.0.19045.1.2", "10.0.19045.-1", "10.0.19045.1000000", "10.0.999", "10.0.19045 ", "11.0.22621"} {
		if _, ok := parseOSVersion(invalid); ok {
			t.Fatal("ambiguous minimum accepted", invalid)
		}
	}
	if CheckHost(nil, preflightPlan()) == nil || CheckInstaller(t.Context(), preflightPlan(), nil) == nil {
		t.Fatal("missing context/stage accepted")
	}
}

func TestSoftwarePreflightCanonicalHelperAndCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r := preflightRequest{Architecture: "amd64", MinimumOS: "10.0.19045"}
	for _, mode := range []string{"compatible", "false", "duplicate", "extra", "oversized", "partial", "error", "wait"} {
		t.Run(mode, func(t *testing.T) {
			timeout := 4 * time.Second
			if mode == "wait" {
				timeout = time.Second
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			started := time.Now()
			command := exec.CommandContext(ctx, executable, "owned-preflight-fixture", mode)
			err := runPreflight(ctx, command, r)
			if (err == nil) != (mode == "compatible") {
				t.Fatal("unsafe preflight helper result", mode, err)
			}
			if err != nil && !errors.Is(err, ErrPreflight) {
				t.Fatal("private helper diagnostic escaped", err)
			}
			if time.Since(started) > 6*time.Second {
				t.Fatal("cancelled helper was not joined")
			}
		})
	}
	for _, input := range []string{`{"architecture":"amd64","minimum_os":"10.0.19045","path":"relative.msi","format":"msi"}`, `{"architecture":"amd64","architecture":"arm64","minimum_os":"10.0.19045"}`, strings.Repeat("x", maxMessage+1)} {
		command := exec.CommandContext(t.Context(), executable, preflightArgument)
		command.Stdin = strings.NewReader(input)
		data, err := command.CombinedOutput()
		if err == nil || len(data) != 0 {
			t.Fatal("invalid native preflight input was not rejected silently", err)
		}
	}
}
