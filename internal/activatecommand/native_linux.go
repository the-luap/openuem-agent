package activatecommand

import (
	"context"
	"errors"

	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/linuxservice"
	"github.com/open-uem/openuem-agent/internal/localready"
)

type linuxController interface {
	Status(context.Context) (linuxservice.Status, error)
	Register(context.Context) error
	Start(context.Context, localready.Identity, string) error
	Close() error
}

type linuxConfiguration interface {
	Prepare(context.Context, []byte) error
	Verify(context.Context) error
	Close() error
}

type linuxInstallation struct {
	controller    linuxController
	configuration linuxConfiguration
	identity      *enrollmentstore.Identity
	registered    bool
}

func prepareNative(ctx context.Context, executable, directory string, identity *enrollmentstore.Identity) (installation, error) {
	return prepareLinux(ctx, executable, directory, identity,
		func(ctx context.Context, spec linuxservice.Spec) (linuxController, error) {
			return linuxservice.Open(ctx, spec)
		},
		func(ctx context.Context, validate func([]byte) bool) (linuxConfiguration, error) {
			return linuxservice.OpenConfiguration(ctx, validate)
		})
}

// The native entry point fixes both providers. Injection is private to tests;
// admitted executable and identity owners remain with run until this closes.
func prepareLinux(ctx context.Context, executable, directory string, identity *enrollmentstore.Identity,
	openController func(context.Context, linuxservice.Spec) (linuxController, error),
	openConfiguration func(context.Context, func([]byte) bool) (linuxConfiguration, error)) (_ *linuxInstallation, resultErr error) {
	if ctx == nil || identity == nil || identity.Keys == nil || identity.Keys.Broker == nil {
		return nil, ErrIdentity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec := linuxservice.Spec{Executable: executable, IdentityDirectory: directory}
	if !spec.Valid() {
		return nil, ErrAccess
	}
	p := &linuxInstallation{identity: identity}
	defer func() {
		if resultErr != nil {
			p.Close()
		}
	}()
	var err error
	p.controller, err = openController(ctx, spec)
	if err != nil {
		return nil, linuxError(err)
	}
	p.configuration, err = openConfiguration(ctx, func(data []byte) bool { return validConfiguration(data, identity) })
	if err != nil {
		return nil, linuxError(err)
	}
	return p, nil
}

func linuxError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, linuxservice.ErrUnit) || errors.Is(err, linuxservice.ErrConfiguration) || errors.Is(err, localready.ErrConflict) {
		return ErrConflict
	}
	if errors.Is(err, linuxservice.ErrStart) {
		return ErrStart
	}
	return ErrRegistration
}

func (p *linuxInstallation) PrepareConfiguration(ctx context.Context) error {
	// Recheck the service before the first configuration mutation. A conflict
	// appearing after Open must not acquire an operational INI on this retry.
	if _, err := p.controller.Status(ctx); err != nil {
		return linuxError(err)
	}
	if err := p.configuration.Prepare(ctx, configuration(p.identity)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrConfiguration
	}
	return nil
}

func (p *linuxInstallation) Register(ctx context.Context) error {
	if err := p.configuration.Verify(ctx); err != nil {
		return linuxError(err)
	}
	if err := p.controller.Register(ctx); err != nil {
		return linuxError(err)
	}
	p.registered = true
	return p.verify(ctx)
}

func (p *linuxInstallation) verify(ctx context.Context) error {
	if err := p.configuration.Verify(ctx); err != nil {
		return linuxError(err)
	}
	status, err := p.controller.Status(ctx)
	if err != nil {
		return linuxError(err)
	}
	if status != linuxservice.Enabled {
		return ErrRegistration
	}
	return nil
}

func (p *linuxInstallation) Start(ctx context.Context) error {
	if err := p.verify(ctx); err != nil {
		return err
	}
	i := p.identity
	public, err := i.Keys.Broker.PublicKey()
	if err != nil {
		return ErrIdentity
	}
	identity := localready.Identity{DeviceID: i.Response.DeviceID, TenantID: i.Response.TenantID, SiteID: i.Response.SiteID,
		ReleaseDigest: i.ReleaseDigest, AgentSize: i.AgentSize, AgentSHA256: i.AgentSHA256, ExpiresAt: i.Response.ExpiresAt}
	if err := p.controller.Start(ctx, identity, public); err != nil {
		return linuxError(err)
	}
	return p.verify(ctx)
}

func (p *linuxInstallation) RegistrationResult() (bool, bool) { return p.registered, false }

func (p *linuxInstallation) Close() error {
	if p.controller != nil {
		p.controller.Close()
		p.controller = nil
	}
	if p.configuration != nil {
		p.configuration.Close()
		p.configuration = nil
	}
	return nil
}
