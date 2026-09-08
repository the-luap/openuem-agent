//go:build !windows && !darwin

package packagesignature

import "context"

func verifyNative(context.Context, string, string) error { return ErrUntrusted }
func HandleHelper(args []string) (bool, int) {
	if len(args) > 0 && args[0] == helperArgument {
		return true, 1
	}
	return false, 0
}
