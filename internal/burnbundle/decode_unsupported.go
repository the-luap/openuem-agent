//go:build !windows || (!amd64 && !arm64)

package burnbundle

import (
	"context"
	"io"
)

func decodeCabinet(context.Context, io.ReaderAt, int64, cabinetIndex) ([]byte, error) {
	return nil, ErrFormat
}
