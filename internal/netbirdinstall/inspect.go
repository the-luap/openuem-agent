package netbirdinstall

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

var ErrMetadata = errors.New("the NetBird package native identity could not be verified")

type packageReader func(context.Context, string, []string, int64, func(io.Reader) error) error

// Inspect checks the native package identity against the entire approved
// descriptor, with byte and file-identity checks before and after inspection.
// It does not authenticate an approval, establish publisher trust on Linux,
// admit an operation, execute package scripts, or report installation success.
// Close cannot remove the package while inspection is running.
func (p *Prepared) Inspect(ctx context.Context, descriptor packageapi.Package) error {
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	if descriptor.Platform != platform || descriptor.Architecture != runtime.GOARCH {
		return ErrMetadata
	}
	return p.inspect(ctx, descriptor, readNativePackage)
}

func (p *Prepared) inspect(ctx context.Context, descriptor packageapi.Package, read packageReader) error {
	if p == nil || ctx == nil || read == nil {
		return ErrMetadata
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.verifyLocked(ctx, descriptor); err != nil {
		return err
	}
	var err error
	switch descriptor.Format {
	case "deb", "rpm":
		err = inspectLinux(ctx, p.path, descriptor, read)
	case "pkg":
		err = inspectMacArchive(ctx, p.file, descriptor.Size, descriptor)
	default:
		err = ErrMetadata
	}
	// A failed inspector cannot hide a concurrent replacement or byte change.
	if changed := p.verifyLocked(ctx, descriptor); changed != nil {
		return changed
	}
	return contextError(ctx, err)
}

func inspectLinux(ctx context.Context, path string, descriptor packageapi.Package, read packageReader) error {
	executable := "/usr/bin/dpkg-deb"
	args := []string{"--show", "--showformat=${Package}\n${Version}\n${Architecture}\n", path}
	architecture := map[string]string{"amd64": "amd64", "arm64": "arm64", "386": "i386"}[descriptor.Architecture]
	expected := descriptor.PackageID + "\n" + descriptor.Version + "\n" + architecture + "\n"
	if descriptor.Format == "rpm" {
		executable = "/usr/bin/rpm"
		// Never read user macros, load plugins, expand a manifest or disable
		// package digest/signature checks. Query mode does not run scriptlets.
		args = []string{"--rcfile", "/dev/null", "--macros", "/dev/null", "--dbpath", "/nonexistent", "--noplugins", "--nomanifest", "--query", "--package", "--queryformat", "%{NAME}\n%{EPOCHNUM}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n", path}
		architecture = map[string]string{"amd64": "x86_64", "arm64": "aarch64", "386": "i386"}[descriptor.Architecture]
	}
	return read(ctx, executable, args, 16<<10, func(reader io.Reader) error {
		data, err := io.ReadAll(io.LimitReader(reader, (16<<10)+1))
		if err != nil || len(data) > 16<<10 || architecture == "" {
			return ErrMetadata
		}
		if descriptor.Format == "deb" {
			if string(data) != expected {
				return ErrMetadata
			}
			return nil
		}
		fields := strings.Split(string(data), "\n")
		if len(fields) != 6 || fields[0] != descriptor.PackageID || fields[4] != architecture || fields[5] != "" || fields[2] == "" || fields[3] == "" {
			return ErrMetadata
		}
		// RPM versions include release and a nonzero epoch. An absent epoch
		// is emitted by EPOCHNUM as 0; no semantic version normalization occurs.
		epoch := fields[1]
		if epoch == "" || len(epoch) > 10 || len(epoch) > 1 && epoch[0] == '0' {
			return ErrMetadata
		}
		for _, c := range epoch {
			if c < '0' || c > '9' {
				return ErrMetadata
			}
		}
		version := fields[2] + "-" + fields[3]
		if epoch != "0" {
			version = epoch + ":" + version
		}
		if version != descriptor.Version {
			return ErrMetadata
		}
		return nil
	})
}
