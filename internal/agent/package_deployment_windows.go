//go:build windows

package agent

import (
	"errors"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-agent/internal/commands/deploy"
)

func (a *Agent) admitPackageTask(task func()) { a.tasks.wrap(task)() }

func (a *Agent) executePackage(operation string, action openuem.DeployAction) (string, string, error) {
	switch operation {
	case "install":
		return deploy.InstallPackageContext(a.ctx, action)
	case "update":
		return deploy.UpdatePackageContext(a.ctx, action)
	case "uninstall":
		return deploy.UninstallPackageContext(a.ctx, action)
	default:
		return "", "", errors.New("unsupported package operation")
	}
}
