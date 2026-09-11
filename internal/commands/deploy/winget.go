//go:build windows

package deploy

import (
	"context"
	"log"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"

	"github.com/open-uem/nats"
	"github.com/open-uem/wingetcfg/wingetcfg"
	"golang.org/x/sys/windows"
)

// Compatibility callers receive the same bounded execution as service callers.
// keepUpdated and debug do not change exit-code interpretation or invoke a shell.
func InstallPackage(action nats.DeployAction, keepUpdated bool, debug bool) (string, string, error) {
	return InstallPackageContext(context.Background(), action)
}

func InstallPackageContext(ctx context.Context, action nats.DeployAction) (string, string, error) {
	return executeWinGet(ctx, "install", action, locateWinGet, runWinGetProcess)
}

func UpdatePackage(action nats.DeployAction) (string, string, error) {
	return UpdatePackageContext(context.Background(), action)
}

func UpdatePackageContext(ctx context.Context, action nats.DeployAction) (string, string, error) {
	return executeWinGet(ctx, "upgrade", action, locateWinGet, runWinGetProcess)
}

func UninstallPackage(action nats.DeployAction) (string, string, error) {
	return UninstallPackageContext(context.Background(), action)
}

func UninstallPackageContext(ctx context.Context, action nats.DeployAction) (string, string, error) {
	return executeWinGet(ctx, "uninstall", action, locateWinGet, runWinGetProcess)
}

func locateWinGet() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", err
	}
	arch := goruntime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	return locateWinGetIn(filepath.Join(root, "WindowsApps"), arch)
}

func GetExplicitelyDeletedPackages(deployments []string, installed string) []string {
	deleted := []string{}

	for _, d := range deployments {
		if !strings.Contains(installed, d) {
			deleted = append(deleted, d)
		}
	}

	return deleted
}

func GetWinGetInstalledPackagesList() (string, error) {
	wgPath, err := locateWinGet()
	if err != nil {
		log.Printf("[ERROR]: could not locate the winget.exe command %v", err)
		return "", err
	}

	out, err := exec.Command(wgPath, "list").Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func RemovePackagesFromCfg(cfg *wingetcfg.WinGetCfg, explicitelyDeleted []string, exclusions []string, installed string, debug bool) error {
	if debug {
		log.Println("[DEBUG]: Installed packages ", installed)
	}

	validResources := []*wingetcfg.WinGetResource{}
	for _, r := range cfg.Properties.Resources {
		if r.Resource == wingetcfg.WinGetPackageResource {
			isPackageExcluded := slices.Contains(exclusions, r.Settings["id"].(string))
			isPackageExplicitelyDeleted := slices.Contains(explicitelyDeleted, r.Settings["id"].(string))
			isAlreadyInstalled := strings.Contains(installed, r.Settings["id"].(string))
			isInstallAction := r.Settings["Ensure"].(string) == "Present"

			if debug {
				log.Printf("[DEBUG]: Package %s, Is installed? %t, Excluded? %t, Explicitely Deleted %t,", r.Settings["id"], isAlreadyInstalled, isPackageExcluded, isPackageExplicitelyDeleted)
			}

			if !isPackageExcluded && !isPackageExplicitelyDeleted &&
				((isInstallAction && !isAlreadyInstalled) || (!isInstallAction && isAlreadyInstalled)) {
				validResources = append(validResources, r)
			}

		} else {
			validResources = append(validResources, r)
		}
	}

	cfg.Properties.Resources = validResources

	return nil
}

type PowerShellTask struct {
	ID        string
	Script    string
	RunConfig string
}

func RemovePowershellScriptsFromCfg(cfg *wingetcfg.WinGetCfg) map[string]PowerShellTask {
	scripts := map[string]PowerShellTask{}
	validResources := []*wingetcfg.WinGetResource{}
	for _, r := range cfg.Properties.Resources {
		if r.Resource == wingetcfg.OpenUEMPowershell {
			script, ok := r.Settings["Script"]
			if ok {
				name, ok := r.Settings["Name"]
				if ok {
					id, ok := r.Settings["ID"]
					if ok {
						scriptRun, ok := r.Settings["ScriptRun"]
						if ok {
							scripts[name.(string)] = PowerShellTask{
								Script:    script.(string),
								RunConfig: scriptRun.(string),
								ID:        id.(string),
							}
						} else {
							scripts[name.(string)] = PowerShellTask{
								Script:    script.(string),
								RunConfig: "once",
								ID:        id.(string),
							}
						}
					}

				}
			}
		} else {
			validResources = append(validResources, r)
		}
	}

	cfg.Properties.Resources = validResources

	return scripts
}
