package windowssoftware

import (
	"context"
	"errors"
	"slices"

	"github.com/open-uem/nats/enrollment"
)

type installerStage interface {
	Path() string
	Verify(context.Context) error
	Close() error
}
type installerProcess struct {
	Started  bool
	ExitCode *uint32
}
type installerOperations struct {
	host    func(context.Context, enrollment.SoftwarePlan) error
	observe func(context.Context, Rule) (Observation, error)
	stage   func(context.Context, enrollment.SoftwarePlan, string) (installerStage, error)
	inspect func(context.Context, enrollment.SoftwarePlan, installerStage) error
	run     func(context.Context, enrollment.SoftwarePlan, string) (installerProcess, error)
}

// Execute consumes an authenticated plan only after its caller has exclusively
// and durably admitted an attempt. It cannot admit/retry tasks itself. The live
// callback revalidates the held installation service lease immediately before
// process start; the caller retains that lease and joins this call on shutdown.
func Execute(ctx context.Context, plan enrollment.SoftwarePlan, root string, live func() error) enrollment.SoftwareOutcome {
	return executeInstaller(ctx, plan, root, live, nativeInstallerOperations())
}

func executeInstaller(ctx context.Context, plan enrollment.SoftwarePlan, root string, live func() error, ops installerOperations) (out enrollment.SoftwareOutcome) {
	unknown := enrollment.SoftwareObservation{State: Unknown}
	out = enrollment.SoftwareOutcome{State: "not_started", Execution: "not_started", Before: unknown, After: unknown, Error: "unavailable"}
	if ctx == nil || ctx.Err() != nil || !plan.Valid() || live == nil || live() != nil || ops.host == nil || ops.observe == nil || ops.stage == nil || ops.inspect == nil || ops.run == nil {
		return out
	}
	rule := Rule{Kind: plan.Detection.Kind, ProductCode: plan.Detection.ProductCode, UninstallKey: plan.Detection.UninstallKey, RegistryView: plan.Detection.RegistryView, Version: plan.Detection.Version}
	observe := func() (enrollment.SoftwareObservation, bool) {
		value, err := ops.observe(ctx, rule)
		if err != nil || !value.valid() || ctx.Err() != nil {
			return unknown, false
		}
		return enrollment.SoftwareObservation{State: value.State, Version: value.Version}, true
	}
	reached := func(value enrollment.SoftwareObservation) bool {
		if plan.Operation == "remove" {
			return value.State == Absent
		}
		return value.Matches(plan.Detection)
	}
	before, ok := observe()
	if !ok {
		out.Error = "detection"
		return out
	}
	out.Before = before
	if reached(before) {
		out.State, out.Error, out.After = "observed", "", before
		return out
	}
	if before.State == Present && !before.Matches(plan.Detection) {
		out.Error = "version_conflict"
		return out
	}
	if err := ops.host(ctx, plan); err != nil {
		out.Error = "incompatible"
		return out
	}
	path := ""
	var stage installerStage
	if plan.Artifact.Valid() {
		var err error
		stage, err = ops.stage(ctx, plan, root)
		if stage != nil {
			defer stage.Close()
		}
		if err != nil || stage == nil {
			out.Error = "download"
			if errors.Is(err, ErrArtifactSignature) {
				out.Error = "signature"
			}
			if errors.Is(err, ErrArtifactChanged) {
				out.Error = "changed_file"
			}
			return out
		}
		if ops.inspect(ctx, plan, stage) != nil {
			out.Error = "preflight"
			return out
		}
		path = stage.Path()
		if path == "" || stage.Verify(ctx) != nil {
			out.Error = "changed_file"
			return out
		}
	}
	// Download and trust evaluation may take minutes. Re-read exact software
	// state so an independent change cannot silently become an upgrade/removal.
	fresh, ok := observe()
	if !ok {
		out.Error = "detection"
		return out
	}
	if reached(fresh) {
		out.State, out.Error, out.Before, out.After = "observed", "", fresh, fresh
		return out
	}
	if fresh != before {
		out.Error = "version_conflict"
		return out
	}
	if ctx.Err() != nil || live() != nil {
		out.Error = "unavailable"
		return out
	}
	if stage != nil && stage.Verify(ctx) != nil {
		out.Error = "changed_file"
		return out
	}
	// This is the last admission check before the native runner resumes a child.
	if ctx.Err() != nil || live() != nil {
		out.Error = "unavailable"
		return out
	}
	process, err := ops.run(ctx, plan, path)
	if !process.Started {
		out.Error = "execution"
		return out
	}
	out.State, out.Execution, out.Error = "uncertain", "started", "execution"
	if process.ExitCode != nil {
		code := *process.ExitCode
		out.ExitCode = &code
	}
	if err != nil {
		return out
	}
	if ctx.Err() != nil || live() != nil {
		out.Error = "interrupted"
		return out
	}
	if process.ExitCode == nil {
		return out
	}
	after, observed := observe()
	out.After = after
	if ctx.Err() != nil || live() != nil {
		out.Error = "interrupted"
		return out
	}
	if slices.Contains(plan.RebootCodes, *process.ExitCode) {
		out.State, out.Error = "restart_required", ""
		return out
	}
	if !slices.Contains(plan.SuccessCodes, *process.ExitCode) {
		out.State = "failed"
		return out
	}
	if !observed || !reached(after) {
		out.Error = "detection"
		return out
	}
	out.State, out.Error = "observed", ""
	return out
}
