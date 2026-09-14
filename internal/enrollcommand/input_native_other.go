//go:build !linux

package enrollcommand

import "github.com/open-uem/nats/enrollment/keyfile"

func readNativeInput(path string, limit int64) ([]byte, error) {
	return readProtectedInput(path, limit)
}

func prepareNativeStaging(path string) error { return keyfile.CreateDirectory(path) }
