//go:build !darwin && !linux

package netbirdinstall

import (
	"context"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func prepareNativeRemoval(context.Context, string, packageapi.Removal) (*Removal, error) {
	return nil, ErrRemoval
}
func nativeInspectRemoval(context.Context) (packageapi.Removal, bool, error) {
	return packageapi.Removal{}, false, ErrRemoval
}

func prepareNativeRemovalRecovery(context.Context, string, packageapi.Removal, string) (*Removal, error) {
	return nil, ErrRemoval
}

func nativeInspectRemovalRecovery(context.Context, string, packageapi.Removal) (string, error) {
	return "", ErrRemoval
}

func nativeInspectRemovalAbsence(context.Context) (string, error)           { return "", ErrRemoval }
func prepareNativeRemovalAbsence(context.Context, string) (*Removal, error) { return nil, ErrRemoval }
