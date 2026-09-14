//go:build !darwin || !cgo

package netbirdinstall

import "context"

func nativeRemovalJob(context.Context) ([]byte, bool, error) { return nil, false, errRemovalProcesses }
