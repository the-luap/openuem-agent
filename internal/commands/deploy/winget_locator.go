package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Only inspect direct children of the protected WindowsApps directory. Never
// search PATH, recurse into unrelated packages, or follow package symlinks.
func locateWinGetIn(root, arch string) (string, error) {
	if arch != "x64" && arch != "arm64" {
		return "", errors.New("unsupported WinGet architecture")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	var selected string
	var latest []int
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		version, ok := strings.CutPrefix(entry.Name(), "Microsoft.DesktopAppInstaller_")
		if !ok {
			continue
		}
		version, ok = strings.CutSuffix(version, "_"+arch+"__8wekyb3d8bbwe")
		if !ok {
			continue
		}
		parts := strings.Split(version, ".")
		if len(parts) != 4 {
			continue
		}
		var numbers []int
		for _, part := range parts {
			n, err := strconv.ParseUint(part, 10, 16)
			if err != nil || strconv.FormatUint(n, 10) != part {
				break
			}
			numbers = append(numbers, int(n))
		}
		if len(numbers) != 4 || (selected != "" && slices.Compare(numbers, latest) <= 0) {
			continue
		}
		candidate := filepath.Join(root, entry.Name(), "winget.exe")
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		selected, latest = candidate, numbers
	}
	if selected == "" {
		return "", errors.New("compatible Desktop App Installer executable not found")
	}
	return selected, nil
}
