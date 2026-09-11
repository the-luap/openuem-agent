//go:build !windows

package windowssoftware

import (
	"os"

	"github.com/open-uem/nats/enrollment/keyfile"
)

func retryStagedRemoval(error, bool) bool { return false }

// Portable tests exercise the stream/hash/cleanup boundary with inert bytes.
// Public Stage rejects non-Windows hosts before reaching this helper.
func openStagedArtifact(path string, size int64) (*os.File, error) { return keyfile.Open(path, size) }
