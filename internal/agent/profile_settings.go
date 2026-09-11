package agent

import (
	"errors"
	"fmt"
	"strings"

	openuem_nats "github.com/open-uem/nats"
	"github.com/open-uem/wingetcfg/wingetcfg"
)

func getEnsureKey(r *wingetcfg.WinGetResource) (string, error) {
	if r == nil {
		return "", errors.New("profile resource is required")
	}
	value, ok := r.Settings["Ensure"].(string)
	if !ok {
		return "", errors.New("could not find the Ensure key")
	}
	if value != "Present" && value != "Absent" {
		return "", errors.New("Ensure must be Present or Absent")
	}

	return value, nil
}

func getStringKey(r *wingetcfg.WinGetResource, key string, maxLength int, required bool) (string, error) {
	if r == nil {
		return "", errors.New("profile resource is required")
	}
	v, ok := r.Settings[key]
	if !ok {
		if required {
			return "", fmt.Errorf("%s is empty and is required", key)
		}
		return "", nil
	}

	value, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	if required && strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is empty and is required", key)
	}

	if maxLength > 0 && len(value) > maxLength {
		return "", fmt.Errorf("%s exceeds the %d character limit", key, maxLength)
	}

	return value, nil
}

func getBoolKey(r *wingetcfg.WinGetResource, key string, required bool) (bool, error) {
	if r == nil {
		return false, errors.New("profile resource is required")
	}
	v, ok := r.Settings[key]
	if !ok {
		if required {
			return false, fmt.Errorf("%s is empty and is required", key)
		}
		return false, nil
	}

	value, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be a boolean", key)
	}

	return value, nil
}

func getCommaSeparatedStringKey(r *wingetcfg.WinGetResource, key string, required bool) (string, error) {
	if r == nil {
		return "", errors.New("profile resource is required")
	}
	v, ok := r.Settings[key]
	if !ok {
		if required {
			return "", fmt.Errorf("%s is empty and is required", key)
		}
		return "", nil
	}

	value, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	values := strings.Split(value, ";")

	csValues := []string{}
	for _, v := range values {
		csValues = append(csValues, fmt.Sprintf("'%s'", v))
	}

	return strings.Join(csValues, ", "), nil
}

type winGetProfileSettings struct {
	Action      openuem_nats.DeployAction
	Ensure      string
	KeepUpdated bool
}

func readWinGetProfileSettings(r *wingetcfg.WinGetResource) (settings winGetProfileSettings, err error) {
	if settings.Ensure, err = getEnsureKey(r); err != nil {
		return settings, err
	}
	if settings.Action.PackageId, err = getStringKey(r, "id", 512, true); err != nil {
		return settings, err
	}
	if settings.Action.PackageVersion, err = getStringKey(r, "version", 512, false); err != nil {
		return settings, err
	}
	if settings.KeepUpdated, err = getBoolKey(r, "uselatest", false); err != nil {
		return settings, err
	}
	source, err := getStringKey(r, "source", 32, false)
	if err != nil {
		return settings, err
	}
	if source != "" && source != "winget" {
		return settings, errors.New("package profile requires the winget source")
	}
	if settings.KeepUpdated && settings.Action.PackageVersion != "" {
		return settings, errors.New("package profile cannot request both a pinned version and the latest version")
	}
	return settings, nil
}
