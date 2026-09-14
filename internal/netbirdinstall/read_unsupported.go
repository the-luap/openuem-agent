//go:build !darwin && !linux

package netbirdinstall

import (
	"context"
	"io"
)

func readNativePackage(context.Context, string, []string, int64, func(io.Reader) error) error {
	return ErrMetadata
}
