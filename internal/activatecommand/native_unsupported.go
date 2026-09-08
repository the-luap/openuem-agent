//go:build !windows && !darwin

package activatecommand

import (
	"context"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
)

func prepareNative(context.Context, string, string, *enrollmentstore.Identity) (installation, error) {
	return nil, ErrUnsupported
}
