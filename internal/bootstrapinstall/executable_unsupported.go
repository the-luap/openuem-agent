//go:build !windows && !darwin && !linux

package bootstrapinstall

import "os"

func openCodeFile(string) (*os.File, error)         { return nil, ErrPackage }
func codeFileProtected(*os.File, os.FileInfo) error { return ErrPackage }
