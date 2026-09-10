package activatecommand

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/localready"
	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const nativeServiceName = "openuem-agent"

type windowsInstallation struct {
	manager                                *mgr.Mgr
	service                                *mgr.Service
	root                                   *os.File
	name, path, identityDirectory, command string
	identity                               *enrollmentstore.Identity
}

func prepareNative(ctx context.Context, path, directory string, identity *enrollmentstore.Identity) (installation, error) {
	return prepareWindows(ctx, path, directory, identity, nativeServiceName)
}

// path is always the retained running executable in production. Every ancestor
// of its installed directory must already be controlled by the trusted installer.
// Tests supply a separate system-owned fixture and unique SCM service name.
func prepareWindows(ctx context.Context, path, directory string, identity *enrollmentstore.Identity, name string) (_ *windowsInstallation, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !nativepath.Valid(path) || !nativepath.Valid(directory) {
		return nil, ErrAccess
	}
	root, err := openProtected(filepath.Dir(path), true, false)
	if err != nil {
		return nil, ErrAccess
	}
	plan := &windowsInstallation{root: root, path: path, identityDirectory: directory, name: name, identity: identity}
	defer func() {
		if resultErr != nil {
			_ = plan.Close()
		}
	}()
	// The service account must be able to access the executable after the elevated
	// installer exits. Reject ordinary user ownership even if that user is admin.
	image, err := openProtected(path, false, false)
	if err != nil {
		return nil, ErrAccess
	}
	_ = image.Close()
	args := []string{path, "serve", "-identity-directory", directory}
	for i := range args {
		args[i] = syscall.EscapeArg(args[i])
	}
	plan.command = strings.Join(args, " ")
	plan.manager, err = mgr.Connect()
	if err != nil {
		return nil, ErrRegistration
	}
	plan.service, err = plan.manager.OpenService(name)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil, ErrRegistration
	}
	if plan.service != nil && plan.matchesService() != nil {
		return nil, ErrConflict
	}
	if err := plan.inspectConfiguration(); err != nil {
		return nil, err
	}
	return plan, nil
}

func (p *windowsInstallation) checkRoot(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.root == nil || protectedObject(p.root, false) != nil {
		return ErrAccess
	}
	before, err := p.root.Stat()
	current, entryErr := os.Lstat(filepath.Dir(p.path))
	if err != nil || entryErr != nil || !os.SameFile(before, current) || !current.IsDir() {
		return ErrAccess
	}
	return nil
}

func (p *windowsInstallation) inspectConfiguration() error {
	for _, name := range []string{"config", "logs"} {
		path := filepath.Join(filepath.Dir(p.path), name)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		file, err := openProtected(path, true, true)
		if err != nil {
			return ErrConflict
		}
		_ = file.Close()
	}
	data, err := readConfiguration(filepath.Join(filepath.Dir(p.path), "config", "openuem.ini"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !validConfiguration(data, p.identity) {
		return ErrConflict
	}
	return nil
}

func (p *windowsInstallation) PrepareConfiguration(ctx context.Context) error {
	if err := p.checkRoot(ctx); err != nil {
		return err
	}
	if p.service != nil && p.matchesService() != nil {
		return ErrConflict
	}
	if err := p.inspectConfiguration(); err != nil {
		return err
	}
	for _, name := range []string{"config", "logs"} {
		file, err := ensurePrivateDirectory(filepath.Join(filepath.Dir(p.path), name))
		if err != nil {
			return ErrConfiguration
		}
		_ = file.Close()
	}
	path := filepath.Join(filepath.Dir(p.path), "config", "openuem.ini")
	if data, err := readConfiguration(path); err == nil {
		if !validConfiguration(data, p.identity) {
			return ErrConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrConfiguration
	}
	if err := publishConfiguration(path, configuration(p.identity)); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrConfiguration
	}
	data, err := readConfiguration(path)
	if err != nil || !validConfiguration(data, p.identity) {
		return ErrConflict
	}
	return nil
}

func (p *windowsInstallation) matchesService() error {
	config, err := p.service.Config()
	if err != nil {
		return ErrRegistration
	}
	if config.BinaryPathName != p.command || config.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || config.StartType != mgr.StartAutomatic || config.ErrorControl != mgr.ErrorNormal || (!strings.EqualFold(config.ServiceStartName, "LocalSystem") && !strings.EqualFold(config.ServiceStartName, `NT AUTHORITY\SYSTEM`)) || len(config.Dependencies) != 0 || config.LoadOrderGroup != "" || config.DelayedAutoStart {
		return ErrConflict
	}
	return nil
}

func (p *windowsInstallation) Register(ctx context.Context) error {
	if err := p.checkRoot(ctx); err != nil {
		return err
	}
	if err := p.inspectConfiguration(); err != nil {
		return err
	}
	if err := p.verifyConfiguration(); err != nil {
		return err
	}
	if p.service != nil {
		return p.matchesService()
	}
	var err error
	p.service, err = p.manager.CreateService(p.name, p.path, mgr.Config{
		ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal, ServiceStartName: "LocalSystem", DisplayName: "OpenUEM Agent",
	}, "serve", "-identity-directory", p.identityDirectory)
	if errors.Is(err, windows.ERROR_SERVICE_EXISTS) || errors.Is(err, windows.ERROR_DUPLICATE_SERVICE_NAME) {
		p.service, err = p.manager.OpenService(p.name)
	}
	if err != nil || p.service == nil {
		return ErrRegistration
	}
	return p.matchesService()
}

func (p *windowsInstallation) Start(ctx context.Context) error {
	if err := p.checkRoot(ctx); err != nil {
		return err
	}
	if p.service == nil {
		return ErrRegistration
	}
	if err := p.matchesService(); err != nil {
		return err
	}
	if err := p.verifyConfiguration(); err != nil {
		return err
	}
	i := p.identity
	public, err := i.Keys.Broker.PublicKey()
	if err != nil {
		return ErrIdentity
	}
	identity := localready.Identity{DeviceID: i.Response.DeviceID, TenantID: i.Response.TenantID, SiteID: i.Response.SiteID, ReleaseDigest: i.ReleaseDigest, AgentSize: i.AgentSize, AgentSHA256: i.AgentSHA256, ExpiresAt: i.Response.ExpiresAt}
	state, err := p.service.Query()
	if err != nil {
		return ErrStart
	}
	if state.State == svc.Stopped {
		if err := p.service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return ErrStart
		}
	} else if state.State != svc.StartPending && state.State != svc.Running {
		return ErrStart
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := p.checkRoot(ctx); err != nil {
			return err
		}
		if err := p.matchesService(); err != nil {
			return err
		}
		state, err = p.service.Query()
		if err != nil || state.State == svc.Stopped || state.State == svc.StopPending {
			return ErrStart
		}
		if state.State == svc.Running && state.ProcessId != 0 {
			pid := state.ProcessId
			err = localready.ProbeProcess(ctx, p.identityDirectory, identity, public, pid)
			if errors.Is(err, localready.ErrConflict) {
				return ErrConflict
			}
			if err == nil {
				// Running also describes a stoppable recovery controller. Require
				// a signed ready proof from this exact live SCM process, then
				// recheck service/configuration before reporting initialization.
				after, queryErr := p.service.Query()
				if queryErr != nil || after.State != svc.Running || after.ProcessId != pid {
					return ErrStart
				}
				if err = p.matchesService(); err != nil {
					return err
				}
				if err = p.checkRoot(ctx); err != nil {
					return err
				}
				return p.verifyConfiguration()
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *windowsInstallation) verifyConfiguration() error {
	data, err := readConfiguration(filepath.Join(filepath.Dir(p.path), "config", "openuem.ini"))
	if err != nil || !validConfiguration(data, p.identity) {
		return ErrConfiguration
	}
	return nil
}

func (p *windowsInstallation) Close() error {
	var first error
	for _, close := range []func() error{
		func() error {
			if p.service == nil {
				return nil
			}
			err := p.service.Close()
			p.service = nil
			return err
		},
		func() error {
			if p.manager == nil {
				return nil
			}
			err := p.manager.Disconnect()
			p.manager = nil
			return err
		},
		func() error {
			if p.root == nil {
				return nil
			}
			err := p.root.Close()
			p.root = nil
			return err
		},
	} {
		if err := close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
