// Package nativepath validates installer-supplied absolute paths without touching
// the filesystem. Native storage/file checks still enforce ownership and access.
package nativepath

import (
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

func Valid(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !utf8.ValidString(path) || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") {
		return false
	}
	if runtime.GOOS == "windows" {
		volume := filepath.VolumeName(path)
		return len(volume) == 2 && volume[1] == ':' && ((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z'))
	}
	return true
}
