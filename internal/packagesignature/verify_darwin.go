package packagesignature

import (
	"context"
	"os/exec"
	"strings"
)

func verifyNative(ctx context.Context, path, format string) error {
	// Never add assessment rules, disable Gatekeeper, remove quarantine, or
	// accept a local override as evidence that Apple notarized the package.
	command := exec.CommandContext(ctx, "/usr/sbin/spctl", "--assess", "--type", "install", "--verbose=2", "--ignore-cache", "--no-cache", path)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	data, err := runCheck(ctx, command)
	defer clear(data)
	if err != nil {
		return err
	}
	if !notarizedAssessment(data) {
		return ErrUntrusted
	}
	return nil
}

func notarizedAssessment(data []byte) bool {
	// Apple documents this exact source value as evidence of notarization.
	// A merely accepted Developer ID, Apple System or local rule is insufficient.
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "source=") {
			if line != "source=Notarized Developer ID" {
				return false
			}
			count++
		}
	}
	return count == 1
}

func HandleHelper(args []string) (bool, int) {
	if len(args) > 0 && args[0] == helperArgument {
		return true, 1
	}
	return false, 0
}
