//go:build openuem_burn_test

package deploy

import (
	"context"
	"errors"

	"github.com/open-uem/nats/enrollment"
)

// RunOwnedBurnProcessFixture preserves the production command builder and native
// runner, exposing only the runner error for generated owned fixture diagnostics.
// Release builds never include this entry point. Output and arguments are omitted.
func RunOwnedBurnProcessFixture(ctx context.Context, plan enrollment.SoftwarePlan, path string) (SoftwareProcessResult, error) {
	if plan.Kind != "windows-burn" {
		return SoftwareProcessResult{}, ErrSoftwareProcess
	}
	var nativeErr error
	result, err := runSoftwareProcess(ctx, plan, path, func(ctx context.Context, executable, command string) (winGetProcessResult, error) {
		var result winGetProcessResult
		result, nativeErr = runWindowsProcess(ctx, executable, command)
		return result, nativeErr
	})
	return result, errors.Join(err, nativeErr)
}
