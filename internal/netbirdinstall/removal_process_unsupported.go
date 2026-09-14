//go:build !darwin || !cgo

package netbirdinstall

import "context"

func removalProcessesSupported() bool                           { return false }
func nativeRemovalPIDs(context.Context) ([]int, error)          { return nil, errRemovalProcesses }
func nativeRemovalPIDPath(context.Context, int) (string, error) { return "", errRemovalProcesses }
func nativeRemovalProcess(context.Context, int, string) (removalProcess, error) {
	return removalProcess{}, errRemovalProcesses
}
func nativeRemovalRecoveryProcess(context.Context, string, int, string) (removalProcess, error) {
	return removalProcess{}, errRemovalProcesses
}
