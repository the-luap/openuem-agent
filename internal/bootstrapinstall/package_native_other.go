//go:build !linux

package bootstrapinstall

import (
	"context"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
)

func stageNativePackage(ctx context.Context, verified *bootstrap.Verified, client *enrollment.HTTPClient, root string, checkpoint artifacts.Checkpoint) (*Package, error) {
	return stagePackage(ctx, verified, client, root, checkpoint, packagesignature.Verify)
}
