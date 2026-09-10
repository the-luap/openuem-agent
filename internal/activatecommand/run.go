// Package activatecommand registers and starts an already enrolled native agent.
// It never consumes invitations, changes identity keys or enrolls another device.
package activatecommand

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/openuem-agent/internal/bootstrapinstall"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/nativepath"
)

var (
	ErrOptions       = errors.New("provide the protected absolute identity directory; use activate -help for usage")
	ErrUnsupported   = errors.New("native service activation is not available on this platform")
	ErrAccess        = errors.New("the installed agent or its protected installation directories are unavailable")
	ErrIdentity      = errors.New("a valid completed individual enrollment and release checkpoint are required")
	ErrConflict      = errors.New("an existing service or configuration belongs to another installation; no replacement was authorized")
	ErrConfiguration = errors.New("the protected operational configuration could not be prepared")
	ErrRegistration  = errors.New("the native agent service could not be registered")
	ErrStart         = errors.New("the registered agent did not prove local readiness; retain the identity and retry after correcting the service error")
	ErrCleanup       = errors.New("activation finished, but local activation resources could not be closed")
	ErrSignature     = errors.New("the installed app requires a valid notarized Developer ID Application signature")
	ErrApproval      = errors.New("the macOS daemon is registered but requires administrator approval in System Settings > General > Login Items; allow OpenUEM Agent, then retry activation")
)

type Options struct{ IdentityDirectory string }

// Running requires authenticated local initialization, never just the native
// controller state or a claim of remote inventory delivery.
type Result struct {
	Registered       bool   `json:"registered"`
	Running          bool   `json:"running"`
	ApprovalRequired bool   `json:"approval_required,omitempty"`
	DeviceID         string `json:"device_id"`
	TenantID         int    `json:"tenant_id"`
	SiteID           int    `json:"site_id"`
}

type identityStore interface {
	Load() (*enrollmentstore.Identity, error)
	Checkpoint() (artifacts.Checkpoint, error)
	Close() error
}
type executable interface {
	InstalledPath() (string, error)
	VerifyStoredBinding(context.Context, int64, string) error
	Close() error
}
type installation interface {
	PrepareConfiguration(context.Context) error
	Register(context.Context) error
	Start(context.Context) error
	Close() error
}
type dependencies struct {
	platform, architecture string
	openExecutable         func() (executable, error)
	openStore              func(string) (identityStore, error)
	prepare                func(context.Context, string, string, *enrollmentstore.Identity) (installation, error)
}

func nativeDependencies() dependencies {
	return dependencies{platform: runtime.GOOS, architecture: runtime.GOARCH,
		openExecutable: func() (executable, error) { return bootstrapinstall.OpenRunningAgent() },
		openStore:      func(path string) (identityStore, error) { return enrollmentstore.Open(path) },
		prepare:        prepareNative,
	}
}

func Run(ctx context.Context, options Options) (Result, error) {
	return run(ctx, options, nativeDependencies())
}

func run(ctx context.Context, options Options, deps dependencies) (result Result, resultErr error) {
	if ctx == nil || !nativepath.Valid(options.IdentityDirectory) {
		return result, ErrOptions
	}
	if (deps.platform != "windows" && deps.platform != "darwin") || (deps.architecture != "amd64" && deps.architecture != "arm64") {
		return result, ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	defer func() {
		if resultErr != nil && ctx.Err() != nil {
			resultErr = ctx.Err()
		}
	}()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	image, err := deps.openExecutable()
	if err != nil {
		return result, ErrAccess
	}
	closeResource := func(close func() error) {
		if err := close(); err != nil && resultErr == nil {
			resultErr = ErrCleanup
		}
	}
	defer closeResource(image.Close)
	path, err := image.InstalledPath()
	if err != nil {
		return result, ErrAccess
	}
	store, err := deps.openStore(options.IdentityDirectory)
	if err != nil {
		return result, ErrIdentity
	}
	defer closeResource(store.Close)
	identity, err := store.Load()
	if err != nil || identity == nil {
		return result, ErrIdentity
	}
	defer identity.Close()
	checkpoint, err := store.Checkpoint()
	identityPlatform := deps.platform
	if identityPlatform == "darwin" {
		identityPlatform = "macos"
	}
	if err != nil || checkpoint.Sequence == 0 || checkpoint.Digest != identity.ReleaseDigest || identity.Platform != identityPlatform || identity.Architecture != deps.architecture || identity.Keys == nil || identity.Keys.Certificate == nil || identity.Keys.Broker == nil || identity.AgentSize <= 0 || identity.AgentSHA256 == "" {
		return result, ErrIdentity
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !identity.Response.ExpiresAt.After(time.Now()) {
			return ErrIdentity
		}
		if current, err := image.InstalledPath(); err != nil || current != path {
			return ErrAccess
		}
		if err := image.VerifyStoredBinding(ctx, identity.AgentSize, identity.AgentSHA256); err != nil {
			return ErrAccess
		}
		return nil
	}
	if err := check(); err != nil {
		return result, err
	}
	// Preflight rejects foreign services/configuration before publishing files.
	install, err := deps.prepare(ctx, path, options.IdentityDirectory, identity)
	if err != nil {
		return result, err
	}
	defer closeResource(install.Close)
	defer func() {
		if reporter, ok := install.(interface{ RegistrationResult() (bool, bool) }); ok {
			registered, approval := reporter.RegistrationResult()
			if registered {
				result.Registered, result.ApprovalRequired = true, approval
				result.DeviceID, result.TenantID, result.SiteID = identity.Response.DeviceID, identity.Response.TenantID, identity.Response.SiteID
			}
		}
	}()
	for _, action := range []func(context.Context) error{install.PrepareConfiguration, install.Register} {
		if err := check(); err != nil {
			return result, err
		}
		if err := action(ctx); err != nil {
			return result, err
		}
	}
	result = Result{Registered: true, DeviceID: identity.Response.DeviceID, TenantID: identity.Response.TenantID, SiteID: identity.Response.SiteID}
	if err := check(); err != nil {
		return result, err
	}
	if err := install.Start(ctx); err != nil {
		return result, err
	}
	if err := check(); err != nil {
		return result, err
	}
	result.Running = true
	return result, nil
}
