//go:build linux || darwin

package agent

import (
	"errors"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-agent/internal/commands/deploy"
)

// Existing Brew/Flatpak executors do not yet own cancellable process trees.
// Preserve their lifecycle until that separate platform work is implemented.
func (a *Agent) admitPackageTask(task func()) { task() }

func (a *Agent) executePackage(operation string, action openuem.DeployAction) (string, string, error) {
	switch operation {
	case "install":
		return deploy.InstallPackage(action, false, a.Config.Debug)
	case "update":
		return deploy.UpdatePackage(action)
	case "uninstall":
		return deploy.UninstallPackage(action)
	default:
		return "", "", errors.New("unsupported package operation")
	}
}
