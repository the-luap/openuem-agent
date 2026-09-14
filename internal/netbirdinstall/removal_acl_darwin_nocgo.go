//go:build darwin && !cgo

package netbirdinstall

import "os"

func removalACL(*os.File) (string, bool) { return "", false }
