package windowssoftware

import (
	"context"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/commands/deploy"
)

func nativeInstallerOperations() installerOperations {
	return installerOperations{host: CheckHost, observe: Observe,
		stage: func(ctx context.Context, plan enrollment.SoftwarePlan, root string) (installerStage, error) {
			return Stage(ctx, plan, root)
		},
		inspect: func(ctx context.Context, plan enrollment.SoftwarePlan, stage installerStage) error {
			retained, ok := stage.(*StagedArtifact)
			if !ok {
				return ErrPreflight
			}
			return CheckInstaller(ctx, plan, retained)
		},
		run: func(ctx context.Context, plan enrollment.SoftwarePlan, path string) (installerProcess, error) {
			result, err := deploy.RunSoftwareProcess(ctx, plan, path)
			return installerProcess{Started: result.Started, ExitCode: result.ExitCode}, err
		},
	}
}
