package activatecommand

import (
	"context"
	"crypto/rsa"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
)

const fixtureDeviceID = "6f73f916-8aaf-4cd1-92e9-c8cbb11028ba"

type fakeImage struct {
	path   string
	err    error
	events *[]string
}

func (f *fakeImage) InstalledPath() (string, error) { return f.path, f.err }
func (f *fakeImage) VerifyStoredBinding(_ context.Context, size int64, digest string) error {
	if size != 1 || digest != strings.Repeat("b", 64) {
		return ErrAccess
	}
	return f.err
}
func (f *fakeImage) Close() error { *f.events = append(*f.events, "image-close"); return nil }

type fakeStore struct {
	identity   *enrollmentstore.Identity
	checkpoint artifacts.Checkpoint
	err        error
	events     *[]string
}

func (f *fakeStore) Load() (*enrollmentstore.Identity, error)  { return f.identity, f.err }
func (f *fakeStore) Checkpoint() (artifacts.Checkpoint, error) { return f.checkpoint, nil }
func (f *fakeStore) Close() error                              { *f.events = append(*f.events, "store-close"); return nil }

type fakeInstallation struct {
	events      *[]string
	fail        string
	afterConfig func()
}

func (f *fakeInstallation) PrepareConfiguration(context.Context) error {
	*f.events = append(*f.events, "configuration")
	if f.afterConfig != nil {
		f.afterConfig()
	}
	if f.fail == "configuration" {
		return ErrConfiguration
	}
	return nil
}
func (f *fakeInstallation) Register(context.Context) error {
	*f.events = append(*f.events, "register")
	if f.fail == "register" {
		return ErrRegistration
	}
	return nil
}
func (f *fakeInstallation) Start(context.Context) error {
	*f.events = append(*f.events, "start")
	if f.fail == "start" {
		return ErrStart
	}
	return nil
}
func (f *fakeInstallation) Close() error {
	*f.events = append(*f.events, "installation-close")
	return nil
}

func activationFixture(t *testing.T) (Options, dependencies, *fakeStore, *fakeImage, *fakeInstallation, *[]string) {
	t.Helper()
	var events []string
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	identity := &enrollmentstore.Identity{Keys: &enrollment.Keys{Certificate: &rsa.PrivateKey{}, Broker: key}, Platform: "windows", Architecture: "amd64", ReleaseDigest: strings.Repeat("a", 64), AgentSize: 1, AgentSHA256: strings.Repeat("b", 64), Response: enrollment.Response{DeviceID: fixtureDeviceID, TenantID: 3, SiteID: 4, ExpiresAt: time.Now().Add(time.Hour)}}
	t.Cleanup(func() { identity.Close() })
	store := &fakeStore{identity: identity, checkpoint: artifacts.Checkpoint{Sequence: 42, Digest: identity.ReleaseDigest}, events: &events}
	image := &fakeImage{path: filepath.Join(t.TempDir(), "agent.exe"), events: &events}
	install := &fakeInstallation{events: &events}
	options := Options{IdentityDirectory: filepath.Join(t.TempDir(), "identity")}
	deps := dependencies{platform: "windows", architecture: "amd64", openExecutable: func() (executable, error) { events = append(events, "image-open"); return image, nil }, openStore: func(path string) (identityStore, error) {
		if path != options.IdentityDirectory {
			t.Error("identity directory changed")
		}
		events = append(events, "store-open")
		return store, nil
	}, prepare: func(_ context.Context, path, directory string, id *enrollmentstore.Identity) (installation, error) {
		if path != image.path || directory != options.IdentityDirectory || id != identity {
			t.Error("preflight changed its trusted inputs")
		}
		events = append(events, "prepare")
		return install, nil
	}}
	return options, deps, store, image, install, &events
}

func TestActivationPublishesOnlyNativeServiceReadinessAndJoinsResources(t *testing.T) {
	o, d, s, _, _, events := activationFixture(t)
	result, err := run(context.Background(), o, d)
	if err != nil || !result.Registered || !result.Running || result.DeviceID != fixtureDeviceID || result.TenantID != 3 || result.SiteID != 4 {
		t.Fatal("activation did not retain assigned scope", result, err)
	}
	if s.identity.Keys != nil {
		t.Fatal("activation retained its decoded identity")
	}
	if !reflect.DeepEqual(*events, []string{"image-open", "store-open", "prepare", "configuration", "register", "start", "installation-close", "store-close", "image-close"}) {
		t.Fatal("resource or mutation order changed", *events)
	}
}

func TestActivationRejectsIncompleteExpiredOrUnboundStateBeforeMutations(t *testing.T) {
	for _, kind := range []string{"pending", "expired", "platform", "architecture", "checkpoint", "digest", "unbound"} {
		t.Run(kind, func(t *testing.T) {
			o, d, s, _, _, events := activationFixture(t)
			switch kind {
			case "pending":
				s.err = enrollmentstore.ErrPending
			case "expired":
				s.identity.Response.ExpiresAt = time.Now().Add(-time.Second)
			case "platform":
				s.identity.Platform = "macos"
			case "architecture":
				s.identity.Architecture = "arm64"
			case "checkpoint":
				s.checkpoint.Sequence = 0
			case "digest":
				s.checkpoint.Digest = strings.Repeat("c", 64)
			case "unbound":
				s.identity.AgentSize = 0
				s.identity.AgentSHA256 = ""
			}
			result, err := run(context.Background(), o, d)
			if !errors.Is(err, ErrIdentity) || result.Registered {
				t.Fatal("invalid identity reached activation", result, err)
			}
			for _, event := range *events {
				if event == "prepare" || event == "configuration" || event == "register" {
					t.Fatal("invalid state caused mutation", *events)
				}
			}
		})
	}
}

func TestActivationRetainsRegistrationOnStartFailureAndRechecksAdmission(t *testing.T) {
	for _, phase := range []string{"configuration", "register", "start", "changed-image", "cancel", "expired"} {
		t.Run(phase, func(t *testing.T) {
			o, d, s, image, install, events := activationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			install.fail = phase
			switch phase {
			case "changed-image":
				install.afterConfig = func() { image.err = ErrAccess }
			case "cancel":
				install.afterConfig = cancel
			case "expired":
				install.afterConfig = func() { s.identity.Response.ExpiresAt = time.Now().Add(-time.Second) }
			}
			result, err := run(ctx, o, d)
			if err == nil || result.Running || result.Registered != (phase == "start") {
				t.Fatal("failed phase reported false state", result, err)
			}
			if result.Registered && result.DeviceID != fixtureDeviceID {
				t.Fatal("partial result lost the registered scope")
			}
			if phase == "changed-image" || phase == "cancel" || phase == "expired" {
				for _, event := range *events {
					if event == "register" || event == "start" {
						t.Fatal("changed admission continued activation")
					}
				}
			}
			if s.identity.Keys != nil {
				t.Fatal("failed activation retained its keys")
			}
		})
	}
}

func TestActivationRefusesInvalidContextPathAndUnsupportedPlatform(t *testing.T) {
	o, d, _, _, _, events := activationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := run(ctx, o, d); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := run(nil, o, d); !errors.Is(err, ErrOptions) {
		t.Fatal(err)
	}
	if _, err := run(context.Background(), Options{IdentityDirectory: "relative"}, d); !errors.Is(err, ErrOptions) {
		t.Fatal(err)
	}
	d.platform = "linux"
	if _, err := run(context.Background(), o, d); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if len(*events) != 0 {
		t.Fatal("invalid invocation opened resources")
	}
}
