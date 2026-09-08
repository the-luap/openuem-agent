// Package enrollcommand implements explicit native enrollment from the installed
// agent. Release trust and management scope must be authorized by the operator.
package enrollcommand

import (
	"context"
	"crypto/x509"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-agent/internal/bootstrapinstall"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
)

var (
	ErrOptions       = errors.New("provide an authorized HTTPS origin, organization/site IDs, protected absolute paths and explicit management consent")
	ErrKeys          = errors.New("the independently provisioned release public keys are unavailable or invalid")
	ErrInvitation    = errors.New("the protected invitation file is unavailable or invalid")
	ErrExecutable    = errors.New("the installed agent could not be verified against the approved release")
	ErrStorage       = errors.New("protected enrollment storage or its release checkpoint is unavailable")
	ErrConfiguration = errors.New("the signed enrollment configuration could not be authenticated")
	ErrScope         = errors.New("the signed configuration does not match the authorized invitation, organization or site")
	ErrPackage       = errors.New("the approved installer could not be downloaded and verified")
	ErrEnrollment    = errors.New("enrollment did not complete; retain the original invitation and protected state for recovery")
	ErrCleanup       = errors.New("enrollment completed, but private bootstrap resources could not be closed or removed")
)

// Options are explicit operator authorization, not values inferred from a
// downloaded document or environment variables. Files/directories and all their
// ancestors must be provisioned by the trusted installer or administrator.
type Options struct {
	Origin            string
	TenantID          int
	SiteID            int
	InvitationFile    string
	ReleaseKeysFile   string
	IdentityDirectory string
	StagingDirectory  string
	DeviceName        string
	AcceptManagement  bool
}

// Result contains only public assigned metadata. IdentityReady means protected
// credentials were persisted; service installation/activation is a separate step.
type Result struct {
	IdentityReady bool   `json:"identity_ready"`
	DeviceID      string `json:"device_id"`
	Organization  string `json:"organization"`
	Site          string `json:"site"`
	TenantID      int    `json:"tenant_id"`
	SiteID        int    `json:"site_id"`
	ReleaseDigest string `json:"release_digest"`
	Release       string `json:"release_version"`
}

type stateStore interface {
	Checkpoint() (artifacts.Checkpoint, error)
	EnrollInstalled(context.Context, *bootstrap.Verified, string, *x509.CertPool, func(context.Context) error) (*enrollmentstore.Identity, error)
	Close() error
}

type retainedFile interface {
	Verify(context.Context, *bootstrap.Verified, artifacts.Checkpoint) error
	Close() error
}

// Dependencies are private so production callers cannot replace native storage,
// OS signature checks, executable verification or system HTTPS trust.
type dependencies struct {
	platform, architecture string
	roots                  *x509.CertPool
	openExecutable         func() (retainedFile, error)
	openStore              func(string) (stateStore, error)
	stage                  func(context.Context, *bootstrap.Verified, *enrollment.HTTPClient, string, artifacts.Checkpoint) (retainedFile, error)
}

func nativeDependencies() dependencies {
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	return dependencies{
		platform: platform, architecture: runtime.GOARCH,
		openExecutable: func() (retainedFile, error) { return bootstrapinstall.OpenRunningAgent() },
		openStore:      func(path string) (stateStore, error) { return enrollmentstore.Open(path) },
		stage: func(ctx context.Context, v *bootstrap.Verified, c *enrollment.HTTPClient, path string, checkpoint artifacts.Checkpoint) (retainedFile, error) {
			return bootstrapinstall.StagePackage(ctx, v, c, path, checkpoint)
		},
	}
}

// Run retains the installed executable before any network work, authenticates
// bootstrap/release signatures and exact requested scope, verifies native package
// trust, and only then admits durable enrollment. It makes no automatic retry and
// never executes a downloaded package. Call from the actual installed service
// executable with its native storage privileges (root/elevated administrator).
func Run(ctx context.Context, options Options) (Result, error) {
	return run(ctx, options, nativeDependencies())
}

func run(ctx context.Context, options Options, deps dependencies) (result Result, resultErr error) {
	if ctx == nil || !validOptions(options) {
		return result, ErrOptions
	}
	if (deps.platform != "windows" && deps.platform != "macos") || (deps.architecture != "amd64" && deps.architecture != "arm64") {
		return result, enrollmentstore.ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	defer func() {
		if resultErr != nil && ctx.Err() != nil {
			resultErr = ctx.Err()
		}
	}()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	executable, err := deps.openExecutable()
	if err != nil {
		return result, ErrExecutable
	}
	closeResource := func(close func() error) {
		if err := close(); err != nil && resultErr == nil {
			resultErr = ErrCleanup
		}
	}
	defer closeResource(executable.Close)
	keys, err := loadReleaseKeys(options.ReleaseKeysFile)
	if err != nil {
		return result, ErrKeys
	}
	token, err := loadInvitation(options.InvitationFile)
	if err != nil {
		return result, ErrInvitation
	}
	store, err := deps.openStore(options.IdentityDirectory)
	if err != nil {
		return result, ErrStorage
	}
	defer closeResource(store.Close)
	checkpoint, err := store.Checkpoint()
	if err != nil {
		return result, ErrStorage
	}
	if err := keyfile.CreateDirectory(options.StagingDirectory); err != nil {
		return result, ErrPackage
	}
	client, err := enrollment.NewHTTPClient(options.Origin, deps.roots)
	if err != nil {
		return result, ErrConfiguration
	}
	defer client.CloseIdleConnections()
	keyDocument, err := client.BootstrapKeys(ctx)
	if err != nil {
		return result, ErrConfiguration
	}
	bootstrapKeys, err := bootstrap.ParseOriginKeys(keyDocument, options.Origin)
	clear(keyDocument)
	if err != nil {
		return result, ErrConfiguration
	}
	data, err := client.Configuration(ctx, token)
	if err != nil {
		return result, ErrConfiguration
	}
	verified, err := bootstrap.Verify(data, bootstrap.Trust{Origin: options.Origin, BootstrapKeys: bootstrapKeys, ReleaseKeys: keys, Checkpoint: checkpoint, Platform: deps.platform, Architecture: deps.architecture}, time.Now())
	clear(data)
	if err != nil {
		return result, ErrConfiguration
	}
	config := verified.Config()
	if config.Invitation != token || config.TenantID != options.TenantID || config.SiteID != options.SiteID {
		return result, ErrScope
	}
	if err := executable.Verify(ctx, verified, checkpoint); err != nil {
		return result, ErrExecutable
	}
	staged, err := deps.stage(ctx, verified, client, options.StagingDirectory, checkpoint)
	if err != nil {
		return result, ErrPackage
	}
	defer closeResource(staged.Close)
	// Read before entering EnrollInstalled: its admission callback must never
	// recurse into the store lifetime lock while Close may be waiting for it.
	checkpoint, err = store.Checkpoint()
	if err != nil {
		return result, ErrStorage
	}
	admit := func(ctx context.Context) error {
		if err := executable.Verify(ctx, verified, checkpoint); err != nil {
			return ErrExecutable
		}
		if err := staged.Verify(ctx, verified, checkpoint); err != nil {
			return ErrPackage
		}
		return nil
	}
	identity, err := store.EnrollInstalled(ctx, verified, options.DeviceName, deps.roots, admit)
	if err != nil {
		if errors.Is(err, ErrExecutable) || errors.Is(err, ErrPackage) {
			return result, err
		}
		return result, ErrEnrollment
	}
	defer identity.Close()
	return Result{IdentityReady: true, DeviceID: identity.Response.DeviceID, Organization: config.Organization, Site: config.Site, TenantID: identity.Response.TenantID, SiteID: identity.Response.SiteID, ReleaseDigest: identity.ReleaseDigest, Release: verified.ReleaseVersion()}, nil
}

func validOptions(o Options) bool {
	if !o.AcceptManagement || !enrollment.ValidOrigin(o.Origin) || o.TenantID <= 0 || o.SiteID <= 0 || len(o.DeviceName) > 255 || !utf8.ValidString(o.DeviceName) || strings.ContainsAny(o.DeviceName, "\x00\r\n") {
		return false
	}
	for _, path := range []string{o.InvitationFile, o.ReleaseKeysFile, o.IdentityDirectory, o.StagingDirectory} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !utf8.ValidString(path) || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") {
			return false
		}
		if runtime.GOOS == "windows" {
			volume := filepath.VolumeName(path)
			if len(volume) != 2 || volume[1] != ':' || !((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z')) {
				return false
			}
		}
	}
	return o.IdentityDirectory != o.StagingDirectory
}
