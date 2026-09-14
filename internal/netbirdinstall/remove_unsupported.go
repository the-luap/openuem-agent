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
