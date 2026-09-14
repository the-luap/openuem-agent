package netbirdinstall

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync"

	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
)

var ErrInstallation = errors.New("the NetBird native installation could not be confirmed")

type installedFile struct {
	size       int64
	hash       [32]byte
	executable bool
}

type installationBackend struct {
	source    func(context.Context, string) error
	signature func(context.Context, string, string) error
	preflight func(context.Context, map[string]installedFile) error
	run       func(context.Context, string, []string) error
	result    func(context.Context, packageapi.Package, map[string]installedFile) error
}

// Installation owns the Prepared mutex until Close. Its native process can only
// use the retained fixed package path, never a path supplied in a wire message.
// The service must durably admit its exact command before calling Run and retain
// this owner through completion, including cancellation and result verification.
type Installation struct {
	mu          sync.Mutex
	prepared    *Prepared
	descriptor  packageapi.Package
	files       map[string]installedFile
	backend     installationBackend
	ran, closed bool
}

func (*Installation) String() string               { return "[private NetBird installation]" }
func (i *Installation) GoString() string           { return i.String() }
func (*Installation) MarshalJSON() ([]byte, error) { return nil, ErrInstallation }

// InstallationSupported never elevates privileges. Linux needs independent
// publisher verification and Windows uses its separate software lifecycle.
func InstallationSupported() bool {
	return runtime.GOOS == "darwin" && os.Geteuid() == 0 && nativeInstallerAvailable()
}

func (p *Prepared) PrepareInstallation(ctx context.Context, descriptor packageapi.Package) (*Installation, error) {
	if !InstallationSupported() || descriptor.Platform != "macos" || descriptor.Architecture != runtime.GOARCH {
		return nil, ErrInstallation
	}
	return p.prepareInstallation(ctx, descriptor, installationBackend{
		source:    nativeInstallationSource,
		signature: packagesignature.Verify,
		preflight: nativeInstallationPreflight,
		run:       runNativeInstaller,
		result:    nativeInstallationResult,
	})
}

func (p *Prepared) prepareInstallation(ctx context.Context, descriptor packageapi.Package, backend installationBackend) (*Installation, error) {
	if p == nil || ctx == nil || descriptor.Platform != "macos" || !descriptor.Valid() || backend.source == nil || backend.signature == nil || backend.preflight == nil || backend.run == nil || backend.result == nil {
		return nil, ErrInstallation
	}
	p.mu.Lock()
	failed := true
	defer func() {
		if failed {
			p.mu.Unlock()
		}
	}()
	if backend.source(ctx, p.path) != nil {
		return nil, ErrInstallation
	}
	if err := p.verifyLocked(ctx, descriptor); err != nil {
		return nil, err
	}
	files := make(map[string]installedFile)
	if err := inspectMacArchiveEvidence(ctx, p.file, descriptor.Size, descriptor, files); err != nil || len(files) == 0 {
		return nil, ErrMetadata
	}
	if err := backend.signature(ctx, p.path, descriptor.Format); err != nil {
		return nil, ErrSignature
	}
	if err := p.verifyLocked(ctx, descriptor); err != nil {
		return nil, err
	}
	if backend.preflight(ctx, files) != nil || ctx.Err() != nil {
		return nil, ErrInstallation
	}
	failed = false
	return &Installation{prepared: p, descriptor: descriptor, files: files, backend: backend}, nil
}

// Run attempts the fixed system installer once and verifies its native receipt
// and every regular payload file. Successful execution alone is insufficient.
// This method is not an admission API; its caller must already own a journal start.
func (i *Installation) Run(ctx context.Context) error {
	if i == nil || ctx == nil {
		return ErrInstallation
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed || i.ran || ctx.Err() != nil {
		return ErrInstallation
	}
	i.ran = true
	if i.backend.source(ctx, i.prepared.path) != nil || i.prepared.verifyLocked(ctx, i.descriptor) != nil || i.backend.preflight(ctx, i.files) != nil {
		return ErrInstallation
	}
	if i.backend.run(ctx, "/usr/sbin/installer", []string{"-pkg", i.prepared.path, "-target", "/"}) != nil || ctx.Err() != nil {
		return ErrInstallation
	}
	if i.prepared.verifyLocked(ctx, i.descriptor) != nil || i.backend.result(ctx, i.descriptor, i.files) != nil || ctx.Err() != nil {
		return ErrInstallation
	}
	return nil
}

// Close joins Run and releases the private file to its original Prepared owner.
// That owner, rather than this plan, remains responsible for deleting the stage.
func (i *Installation) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.closed {
		i.closed = true
		i.prepared.mu.Unlock()
	}
	return nil
}
