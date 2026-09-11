//go:build !windows

package windowssoftware

import "context"

func observeNative(context.Context, Rule) (Observation, error) {
	return Observation{State: Unknown}, ErrObservation
}
func readNative(Rule) (Observation, error) { return Observation{State: Unknown}, ErrObservation }
