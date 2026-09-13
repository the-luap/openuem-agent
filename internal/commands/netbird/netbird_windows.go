//go:build windows

package netbird

import (
	"log"

	openuem_nats "github.com/open-uem/nats"
	"github.com/open-uem/openuem-agent/internal/commands/deploy"
	"github.com/open-uem/openuem-agent/internal/commands/report"
)

func Install() (*openuem_nats.Netbird, error) {
	action := openuem_nats.DeployAction{
		PackageId: "Netbird.Netbird",
	}

	if _, _, err := deploy.InstallPackage(action, false, false); err != nil {
		log.Printf("[ERROR]: could not install the NetBird client, reason: %v", err)
		return nil, err
	}

	return report.RetrieveNetbirdInfo()
}

func Uninstall() error {
	action := openuem_nats.DeployAction{
		PackageId: "Netbird.Netbird",
	}

	if _, _, err := deploy.UninstallPackage(action); err != nil {
		log.Printf("[ERROR]: could not uninstall the NetBird client, reason: %v", err)
		return err
	}
	return nil
}
