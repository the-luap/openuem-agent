package activatecommand

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/localready"
	"github.com/open-uem/openuem-agent/internal/macbundle"
	"github.com/open-uem/openuem-agent/internal/macservice"
)

type macController interface {
	Status(context.Context) (macservice.Status, error)
	Register(context.Context) (macservice.Status, error)
	Close() error
}

type macSettings struct {
	base, logs    string
	ancestors     []string
	uid           uint32
	checkVarAlias bool
}

type macInstallation struct {
	controller                   macController
	settings                     macSettings
	identity                     *enrollmentstore.Identity
	directory, config            string
	parents                      []*os.File
	privateParents               []*os.File
	registered, approvalRequired bool
	probe                        func(context.Context, string, localready.Identity, string) error
}

func prepareNative(ctx context.Context, path, directory string, identity *enrollmentstore.Identity) (installation, error) {
	if os.Geteuid() != 0 || directory != macbundle.IdentityDirectory {
		return nil, ErrAccess
	}
	return prepareMac(ctx, path, directory, identity, macSettings{
		base: "/Library/OpenUEMAgent", logs: "/private/var/log/openuem-agent", uid: 0,
		ancestors: []string{"/", "/Library", "/private", "/private/var", "/private/var/log"}, checkVarAlias: true,
	}, func(ctx context.Context, path string) (macController, error) { return macservice.Open(ctx, path) }, localready.Probe)
}

func prepareMac(ctx context.Context, path, directory string, identity *enrollmentstore.Identity, settings macSettings,
	open func(context.Context, string) (macController, error), probe func(context.Context, string, localready.Identity, string) error) (_ *macInstallation, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	controller, err := open(ctx, path)
	if err != nil {
		return nil, macError(err)
	}
	p := &macInstallation{controller: controller, settings: settings, identity: identity, directory: directory, config: filepath.Join(settings.base, "etc/openuem-agent/openuem.ini"), probe: probe}
	defer func() {
		if resultErr != nil {
			p.Close()
		}
	}()
	for _, parent := range append(append([]string{}, settings.ancestors...), settings.base) {
		file, err := openMacProtected(parent, true, false, settings.uid)
		if err != nil {
			return nil, ErrAccess
		}
		p.parents = append(p.parents, file)
	}
	identityRoot, err := openMacProtected(directory, true, true, settings.uid)
	if err != nil {
		return nil, ErrAccess
	}
	p.privateParents = append(p.privateParents, identityRoot)
	if err := p.check(ctx); err != nil {
		return nil, err
	}
	status, err := controller.Status(ctx)
	if err != nil || status > macservice.RequiresApproval {
		return nil, macError(err)
	}
	if err := p.inspectConfiguration(); err != nil {
		return nil, err
	}
	return p, nil
}

func macError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, macservice.ErrUnsupported) {
		return ErrUnsupported
	}
	if errors.Is(err, macservice.ErrAccess) {
		return ErrAccess
	}
	if errors.Is(err, macservice.ErrSignature) {
		return ErrSignature
	}
	return ErrRegistration
}

func (p *macInstallation) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.settings.checkVarAlias {
		// The logger uses macOS's standard /var alias. Validate it while working
		// through canonical /private/var paths; never follow a supplied alias.
		info, err := os.Lstat("/var")
		target, linkErr := os.Readlink("/var")
		if err != nil || linkErr != nil || info.Mode()&os.ModeSymlink == 0 || target != "private/var" {
			return ErrAccess
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return ErrAccess
		}
	}
	for _, private := range []bool{false, true} {
		files := p.parents
		if private {
			files = p.privateParents
		}
		for _, file := range files {
			opened, err := file.Stat()
			current, entryErr := os.Lstat(file.Name())
			if err != nil || entryErr != nil || !os.SameFile(opened, current) || !macProtected(opened, true, private, p.settings.uid) || !macProtected(current, true, private, p.settings.uid) {
				return ErrAccess
			}
		}
	}
	return nil
}

func (p *macInstallation) inspectConfiguration() error {
	for _, path := range []string{filepath.Join(p.settings.base, "etc"), filepath.Dir(p.config), p.settings.logs} {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		file, err := openMacProtected(path, true, true, p.settings.uid)
		if err != nil {
			return ErrConflict
		}
		file.Close()
	}
	data, err := readMacConfiguration(p.config, p.settings.uid)
	missing := errors.Is(err, os.ErrNotExist)
	if !missing && (err != nil || !validConfiguration(data, p.identity)) {
		return ErrConflict
	}
	logPath := filepath.Join(p.settings.logs, "openuem-agent.log")
	log, logErr := openMacProtected(logPath, false, true, p.settings.uid)
	if logErr == nil {
		log.Close()
		if missing {
			return ErrConflict
		}
	} else if !errors.Is(logErr, os.ErrNotExist) {
		return ErrConflict
	}
	return nil
}

func (p *macInstallation) PrepareConfiguration(ctx context.Context) error {
	if err := p.check(ctx); err != nil {
		return err
	}
	if err := p.inspectConfiguration(); err != nil {
		return err
	}
	for _, path := range []string{filepath.Join(p.settings.base, "etc"), filepath.Dir(p.config), p.settings.logs} {
		if err := p.check(ctx); err != nil {
			return err
		}
		file, err := ensureMacDirectory(path, p.settings.uid)
		if err != nil {
			return ErrConfiguration
		}
		p.privateParents = append(p.privateParents, file)
	}
	if data, err := readMacConfiguration(p.config, p.settings.uid); err == nil {
		if !validConfiguration(data, p.identity) {
			return ErrConflict
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := publishMacConfiguration(p.config, configuration(p.identity), p.settings.uid); err != nil && !errors.Is(err, os.ErrExist) {
			return ErrConfiguration
		}
	} else {
		return ErrConfiguration
	}
	return p.verifyConfiguration(ctx)
}

func (p *macInstallation) verifyConfiguration(ctx context.Context) error {
	if err := p.check(ctx); err != nil {
		return err
	}
	if err := p.inspectConfiguration(); err != nil {
		return err
	}
	data, err := readMacConfiguration(p.config, p.settings.uid)
	if err != nil || !validConfiguration(data, p.identity) {
		return ErrConfiguration
	}
	return nil
}

func (p *macInstallation) Register(ctx context.Context) error {
	if err := p.verifyConfiguration(ctx); err != nil {
		return err
	}
	status, err := p.controller.Register(ctx)
	p.observe(status)
	if err != nil {
		return macError(err)
	}
	if !p.registered {
		return ErrRegistration
	}
	return nil
}

func (p *macInstallation) observe(status macservice.Status) {
	p.registered = status == macservice.Enabled || status == macservice.RequiresApproval
	p.approvalRequired = status == macservice.RequiresApproval
}

func (p *macInstallation) RegistrationResult() (bool, bool) { return p.registered, p.approvalRequired }

func (p *macInstallation) Start(ctx context.Context) error {
	if err := p.verifyConfiguration(ctx); err != nil {
		return err
	}
	i := p.identity
	public, err := i.Keys.Broker.PublicKey()
	if err != nil {
		return ErrIdentity
	}
	identity := localready.Identity{DeviceID: i.Response.DeviceID, TenantID: i.Response.TenantID, SiteID: i.Response.SiteID, ReleaseDigest: i.ReleaseDigest, AgentSize: i.AgentSize, AgentSHA256: i.AgentSHA256, ExpiresAt: i.Response.ExpiresAt}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := p.check(ctx); err != nil {
			return err
		}
		status, err := p.controller.Status(ctx)
		if err != nil {
			return macError(err)
		}
		p.observe(status)
		if p.approvalRequired {
			return ErrApproval
		}
		if !p.registered {
			return ErrRegistration
		}
		err = p.probe(ctx, p.directory, identity, public)
		if err == nil {
			status, err := p.controller.Status(ctx)
			if err != nil {
				return macError(err)
			}
			p.observe(status)
			if p.approvalRequired {
				return ErrApproval
			}
			if !p.registered {
				return ErrRegistration
			}
			return p.verifyConfiguration(ctx)
		}
		if errors.Is(err, localready.ErrConflict) {
			return ErrConflict
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *macInstallation) Close() error {
	var first error
	if p.controller != nil {
		first = p.controller.Close()
		p.controller = nil
	}
	for _, file := range append(p.parents, p.privateParents...) {
		if err := file.Close(); first == nil {
			first = err
		}
	}
	p.parents, p.privateParents = nil, nil
	return first
}
