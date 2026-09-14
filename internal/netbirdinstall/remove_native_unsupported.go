//go:build !darwin || !cgo

package netbirdinstall

import "context"

func nativeRemovalExecutionAvailable() bool                                  { return false }
func nativeSignalRemovalProcess(context.Context, removalProcess, bool) error { return ErrRemoval }
func removalProcessesQuiet(context.Context, []removalProcess) (bool, error)  { return false, ErrRemoval }
func nativeSignalRemovalRecoveryProcess(context.Context, string, removalProcess, bool) error {
	return ErrRemoval
}
func removalRecoveryProcessesQuiet(context.Context, string, []removalProcess) (bool, error) {
	return false, ErrRemoval
}
