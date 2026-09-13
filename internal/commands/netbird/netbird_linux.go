//go:build linux

package netbird

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"

	openuem_nats "github.com/open-uem/nats"
	"github.com/open-uem/openuem-agent/internal/commands/report"
	"github.com/open-uem/openuem-agent/internal/commands/runtime"
)

func Install() (*openuem_nats.Netbird, error) {
	var err error

	command := "curl -fsSL https://pkgs.netbird.io/install.sh | sh"
	c1 := exec.Command("bash", "-c", command)

	if hasGraphicalDesktop() {
		c1.Env = os.Environ()
		c1.Env = append(c1.Env, "XDG_CURRENT_DESKTOP=OpenUEM")
	}

	out, err := c1.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR]: could not install the NetBird client, reason: %s", string(out))
		return nil, errors.New(string(out))
	}

	return report.RetrieveNetbirdInfo()
}

func Uninstall() error {
	var err error

	command := "curl -fsSL https://downloads.openuem.eu/netbird/netbird_uninstall.sh | sh"
	c1 := exec.Command("bash", "-c", command)
	desktop, err := runtime.GetUserEnv("XDG_CURRENT_DESKTOP")
	if err == nil {
		c1.Env = os.Environ()
		c1.Env = append(c1.Env, fmt.Sprintf("XDG_CURRENT_DESKTOP=%s", desktop))
	}

	out, err := c1.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR]: could not install the NetBird client, reason: %s", string(out))
		return errors.New(string(out))
	}

	return nil
}

func hasGraphicalDesktop() bool {
	hasXOrg := false
	hasXWayland := false

	if err := exec.Command("bash", "-c", "type Xorg").Run(); err == nil {
		hasXOrg = true
	}

	if err := exec.Command("bash", "-c", "type Xwayland").Run(); err == nil {
		hasXWayland = true
	}

	return hasXOrg || hasXWayland
}
