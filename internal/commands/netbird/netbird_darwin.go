//go:build darwin

package netbird

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"

	openuem_nats "github.com/open-uem/nats"
	"github.com/open-uem/openuem-agent/internal/commands/report"
)

func Install() (*openuem_nats.Netbird, error) {
	var err error

	command := "curl -fsSL https://pkgs.netbird.io/install.sh | sh"
	c1 := exec.Command("bash", "-c", command)

	out, err := c1.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR]: could not install the NetBird client, reason: %s", string(out))
		return nil, errors.New(string(out))
	}

	// it seems that the netbird install doesn't create the /var/lib/netbird/default.json
	// in certain circumstances
	if _, err := os.Stat("/var/lib/netbird/default.json"); err != nil {
		if err := os.MkdirAll("/var/lib/netbird", 0750); err != nil {
			return nil, err
		}

		f, err := os.Create("/var/lib/netbird/default.json")
		if err != nil {
			return nil, err
		}
		defer func() { f.Close() }()

		data, err := json.Marshal(struct{}{})
		if err != nil {
			return nil, err
		}

		if _, err := f.Write(data); err != nil {
			return nil, err
		}

	}

	return report.RetrieveNetbirdInfo()
}

func Uninstall() error {
	var err error

	command := "curl -fsSL https://downloads.openuem.eu/netbird/netbird_uninstall.sh | sh"
	c1 := exec.Command("bash", "-c", command)

	out, err := c1.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR]: could not install the NetBird client, reason: %s", string(out))
		return errors.New(string(out))
	}

	return nil
}
