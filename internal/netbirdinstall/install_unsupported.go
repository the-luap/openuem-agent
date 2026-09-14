//go:build !darwin && !linux

package netbirdinstall

import (
	"context"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func runNativeInstaller(context.Context, string, []string) error { return ErrInstallation }
func nativeInstallationSource(context.Context, string) error     { return ErrInstallation }
func nativeInstallationPreflight(context.Context, map[string]installedFile) error {
	return ErrInstallation
}
func nativeInstallationResult(context.Context, packageapi.Package, map[string]installedFile) error {
	return ErrInstallation
}
