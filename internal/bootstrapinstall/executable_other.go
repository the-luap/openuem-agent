//go:build !linux

package bootstrapinstall

func openLinuxRunningAgent() (*Executable, error) { return nil, ErrPackage }
