package windowssoftware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

var ErrPreflight = errors.New("the approved Windows installer is not compatible with this device")

const preflightArgument = "--openuem-check-windows-installer"

type preflightRequest struct {
	Architecture string `json:"architecture"`
	MinimumOS    string `json:"minimum_os"`
	Path         string `json:"path,omitempty"`
	Format       string `json:"format,omitempty"`
	Detection    *Rule  `json:"detection,omitempty"`
}
type preflightResponse struct {
	Compatible bool `json:"compatible"`
}

func (r preflightRequest) valid() bool {
	if r.Architecture != "amd64" && r.Architecture != "arm64" {
		return false
	}
	if _, ok := parseOSVersion(r.MinimumOS); !ok {
		return false
	}
	if r.Path == "" {
		return r.Format == "" && r.Detection == nil
	}
	extension := r.Format
	if r.Format == "burn" {
		extension = "exe"
	}
	if !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path || strings.ContainsAny(r.Path, "\x00\r\n\"") || !strings.EqualFold(filepath.Ext(r.Path), "."+extension) {
		return false
	}
	if r.Format == "exe" {
		return r.Detection == nil
	}
	if r.Format == "burn" {
		return r.Detection != nil && validBurnRule(*r.Detection)
	}
	return r.Format == "msi" && r.Detection != nil && r.Detection.Kind == "msi-product" && r.Detection.Validate() == nil
}

func validBurnRule(r Rule) bool {
	if r.Validate() != nil || r.Kind != "uninstall-key" || r.RegistryView != "64" {
		return false
	}
	id, err := uuid.Parse(r.UninstallKey)
	return err == nil && id != uuid.Nil && r.UninstallKey == "{"+strings.ToUpper(id.String())+"}"
}

func parseOSVersion(text string) ([4]uint32, bool) {
	var version [4]uint32
	parts := strings.Split(text, ".")
	if len(parts) != 3 && len(parts) != 4 || parts[0] != "10" || parts[1] != "0" {
		return version, false
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != part {
			return version, false
		}
		version[i] = uint32(n)
	}
	return version, version[2] >= 1000 && version[2] <= 99999 && version[3] <= 999999
}

func compatibleOS(minimum string, actual [4]uint32) bool {
	want, ok := parseOSVersion(minimum)
	if !ok || actual[0] != 10 || actual[1] != 0 {
		return false
	}
	for i := range actual {
		if actual[i] != want[i] {
			return actual[i] > want[i]
		}
	}
	return true
}

// CheckHost reads native architecture and OS evidence through a bounded helper.
// Registry update revision is compatibility evidence, never proof of a reboot.
func CheckHost(ctx context.Context, plan enrollment.SoftwarePlan) error {
	if !plan.Valid() {
		return ErrPreflight
	}
	return checkPreflight(ctx, preflightRequest{Architecture: plan.Architecture, MinimumOS: plan.MinimumOS})
}

// CheckInstaller requires a retained, verified stage. MSI metadata is queried
// read-only; EXE architecture comes from its PE header. Explicit Burn plans also
// require matching embedded machine registration inside the bounded helper.
// No inspection path runs installer code.
func CheckInstaller(ctx context.Context, plan enrollment.SoftwarePlan, stage *StagedArtifact) error {
	if !plan.Valid() || stage == nil || stage.digest != plan.Artifact.SHA256 || stage.Verify(ctx) != nil {
		return ErrPreflight
	}
	r := preflightRequest{Architecture: plan.Architecture, MinimumOS: plan.MinimumOS, Path: stage.Path(), Format: plan.Artifact.Format}
	if r.Format == "msi" {
		r.Detection = &Rule{Kind: "msi-product", ProductCode: plan.Detection.ProductCode, Version: plan.Detection.Version}
	}
	if plan.Kind == "windows-burn" {
		r.Format = "burn"
		r.Detection = &Rule{Kind: plan.Detection.Kind, UninstallKey: plan.Detection.UninstallKey, RegistryView: plan.Detection.RegistryView, Version: plan.Detection.Version}
	}
	if err := checkPreflight(ctx, r); err != nil {
		return err
	}
	if stage.Verify(ctx) != nil {
		return ErrPreflight
	}
	return nil
}

func checkPreflight(ctx context.Context, r preflightRequest) error {
	if ctx == nil || ctx.Err() != nil || !r.valid() {
		return ErrPreflight
	}
	ctx, cancel := context.WithTimeout(ctx, observationTimeout)
	defer cancel()
	return preflightNative(ctx, r)
}

func runPreflight(ctx context.Context, command *exec.Cmd, r preflightRequest) error {
	data, err := json.Marshal(r)
	defer clear(data)
	if err != nil || len(data) > maxMessage {
		return ErrPreflight
	}
	var output boundedOutput
	command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(data), &output, io.Discard
	command.WaitDelay = time.Second
	err = command.Run()
	defer clear(output.data)
	var response preflightResponse
	if err != nil || ctx.Err() != nil || output.overflow || !decodeMessage(output.data, &response) || !response.Compatible {
		return ErrPreflight
	}
	return nil
}

// HandlePreflightHelper runs before service, logging and identity initialization.
// A private pipe carries bounded metadata expectations, never installer options.
func HandlePreflightHelper(args []string) (bool, int) {
	if len(args) == 0 || args[0] != preflightArgument {
		return false, 0
	}
	if len(args) != 1 {
		return true, 1
	}
	deadline := time.AfterFunc(observationTimeout, func() { os.Exit(1) })
	defer deadline.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), observationTimeout)
	defer cancel()
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxMessage+1))
	defer clear(data)
	var r preflightRequest
	if err != nil || !decodeMessage(data, &r) || !r.valid() || readPreflight(ctx, r) != nil || ctx.Err() != nil {
		return true, 1
	}
	if _, err := io.WriteString(os.Stdout, `{"compatible":true}`); err != nil {
		return true, 1
	}
	return true, 0
}
