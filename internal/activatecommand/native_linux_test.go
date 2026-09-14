package activatecommand

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/linuxservice"
	"github.com/open-uem/openuem-agent/internal/localready"
	"golang.org/x/sys/unix"
)

type fakeLinuxController struct {
	state                         linuxservice.Status
	registrations, starts, closes int
	register                      func(context.Context) error
	start                         func(context.Context, localready.Identity, string) error
}

func (c *fakeLinuxController) Status(ctx context.Context) (linuxservice.Status, error) {
	return c.state, ctx.Err()
}
func (c *fakeLinuxController) Register(ctx context.Context) error {
	c.registrations++
	if c.register != nil {
		return c.register(ctx)
	}
	c.state = linuxservice.Enabled
	return ctx.Err()
}
func (c *fakeLinuxController) Start(ctx context.Context, identity localready.Identity, public string) error {
	c.starts++
	if c.start != nil {
		return c.start(ctx, identity, public)
	}
	return ctx.Err()
}
func (c *fakeLinuxController) Close() error { c.closes++; return nil }

func nativeLinuxConfigurationFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENUEM_TEST_LINUX_ACTIVATION") != "owned-isolated-activation" {
		t.Skip("requires the owned Linux activation container")
	}
	if os.Geteuid() != 0 || os.TempDir() != "/fixture" {
		t.Fatal("activation fixture requires owned root tmpfs")
	}
	for _, directory := range []string{linuxservice.ConfigurationDirectory, linuxservice.LogDirectory} {
		var fs unix.Statfs_t
		if unix.Statfs(directory, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
			t.Fatal("operational fixture is not an owned tmpfs")
		}
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			t.Fatal("operational fixture is not empty", err)
		}
		t.Cleanup(func() {
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Error(err)
				return
			}
			for _, entry := range entries {
				if err := os.RemoveAll(filepath.Join(directory, entry.Name())); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func prepareNativeLinuxFixture(t *testing.T, controller *fakeLinuxController) (*linuxInstallation, *enrollmentstore.Identity) {
	t.Helper()
	nativeLinuxConfigurationFixture(t)
	_, _, store, _, _, _ := activationFixture(t)
	store.identity.Platform = "linux"
	p, err := prepareLinux(t.Context(), "/opt/openuem/agent", "/fixture/identity", store.identity,
		func(_ context.Context, spec linuxservice.Spec) (linuxController, error) {
			if spec.Executable != "/opt/openuem/agent" || spec.IdentityDirectory != "/fixture/identity" {
				t.Error("native service specification changed")
			}
			return controller, nil
		}, func(ctx context.Context, validate func([]byte) bool) (linuxConfiguration, error) {
			return linuxservice.OpenConfiguration(ctx, validate)
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p, store.identity
}

func TestLinuxActivationUsesProtectedINIAndExactReadinessIdentity(t *testing.T) {
	controller := &fakeLinuxController{}
	p, identity := prepareNativeLinuxFixture(t, controller)
	filename := filepath.Join(linuxservice.ConfigurationDirectory, "openuem.ini")
	if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preflight published an INI")
	}
	if err := p.PrepareConfiguration(t.Context()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filename)
	if err != nil || !validConfiguration(data, identity) {
		t.Fatal("native configuration lost its enrollment marker", err)
	}
	data = bytes.ReplaceAll(data, []byte("DefaultFrequency = 15"), []byte("DefaultFrequency = 20"))
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.PrepareConfiguration(t.Context()); err != nil {
		t.Fatal("marked administrator settings were not preserved", err)
	}
	if err := p.Register(t.Context()); err != nil {
		t.Fatal(err)
	}
	controller.start = func(_ context.Context, got localready.Identity, public string) error {
		want, _ := identity.Keys.Broker.PublicKey()
		if public != want || got.DeviceID != identity.Response.DeviceID || got.TenantID != identity.Response.TenantID || got.SiteID != identity.Response.SiteID || got.ReleaseDigest != identity.ReleaseDigest || got.AgentSize != identity.AgentSize || got.AgentSHA256 != identity.AgentSHA256 || !got.ExpiresAt.Equal(identity.Response.ExpiresAt) {
			t.Error("service start lost the protected enrollment binding")
		}
		return nil
	}
	if err := p.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if registered, approval := p.RegistrationResult(); !registered || approval {
		t.Fatal("native Linux registration was not reported")
	}
	p.Close()
	if controller.registrations != 1 || controller.starts != 1 || controller.closes != 1 {
		t.Fatal("native provider lifecycle differs", controller)
	}
	retained, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(retained, data) {
		t.Fatal("activation rewrote administrator settings", err)
	}
	if identity.Keys == nil {
		t.Fatal("installation closed its caller-owned identity")
	}
}

func TestLinuxActivationRejectsChangedConfigurationBetweenPhases(t *testing.T) {
	for _, scenario := range []string{"before-register", "before-start", "after-proof", "registration-error", "readiness-conflict", "readiness-unavailable", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			controller := &fakeLinuxController{}
			p, identity := prepareNativeLinuxFixture(t, controller)
			if err := p.PrepareConfiguration(t.Context()); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(linuxservice.ConfigurationDirectory, "openuem.ini")
			change := func() {
				t.Helper()
				if err := os.WriteFile(filename, []byte("owned foreign INI"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "before-register" {
				change()
				if p.Register(t.Context()) == nil || controller.registrations != 0 {
					t.Fatal("changed INI registered a service")
				}
				return
			}
			if scenario == "registration-error" {
				controller.register = func(context.Context) error { return linuxservice.ErrRegistration }
				if !errors.Is(p.Register(t.Context()), ErrRegistration) || controller.starts != 0 {
					t.Fatal("registration failure started a service")
				}
				return
			}
			if err := p.Register(t.Context()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch scenario {
			case "before-start":
				change()
			case "after-proof":
				controller.start = func(context.Context, localready.Identity, string) error { change(); return nil }
			case "readiness-conflict":
				controller.start = func(context.Context, localready.Identity, string) error { return localready.ErrConflict }
			case "readiness-unavailable":
				controller.start = func(context.Context, localready.Identity, string) error { return linuxservice.ErrStart }
			case "canceled":
				cancel()
			}
			err := p.Start(ctx)
			if err == nil {
				t.Fatal("incomplete native activation reported readiness")
			}
			if (scenario == "before-start" || scenario == "canceled") && controller.starts != 0 {
				t.Fatal("rejected preflight started a service")
			}
			if registered, approval := p.RegistrationResult(); !registered || approval {
				t.Fatal("failure lost completed registration evidence")
			}
			p.Close()
			if _, err := os.Lstat(filename); err != nil || identity.Keys == nil {
				t.Fatal("failed activation removed configuration or caller identity", err)
			}
		})
	}
}

func TestLinuxActivationPreflightPreservesForeignConfigurationAndLog(t *testing.T) {
	for _, scenario := range []string{"service", "legacy-ini", "other-device", "unowned-log"} {
		t.Run(scenario, func(t *testing.T) {
			nativeLinuxConfigurationFixture(t)
			_, _, store, _, _, _ := activationFixture(t)
			controller := &fakeLinuxController{}
			filename := filepath.Join(linuxservice.ConfigurationDirectory, "openuem.ini")
			var data []byte
			if scenario == "legacy-ini" {
				data = []byte("[Agent]\nUUID = legacy\n")
			}
			if scenario == "other-device" {
				data = bytes.ReplaceAll(configuration(store.identity), []byte(store.identity.Response.DeviceID), []byte("3af87b56-67d4-4b1e-bc7b-e6f6d3197c3f"))
			}
			if data != nil {
				if err := os.WriteFile(filename, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "unowned-log" {
				if err := os.Symlink("/owned-unrelated", filepath.Join(linuxservice.LogDirectory, "openuem-agent.log")); err != nil {
					t.Fatal(err)
				}
			}
			p, err := prepareLinux(t.Context(), "/opt/openuem/agent", "/fixture/identity", store.identity,
				func(context.Context, linuxservice.Spec) (linuxController, error) {
					if scenario == "service" {
						return nil, linuxservice.ErrUnit
					}
					return controller, nil
				},
				func(ctx context.Context, validate func([]byte) bool) (linuxConfiguration, error) {
					return linuxservice.OpenConfiguration(ctx, validate)
				})
			if p != nil {
				p.Close()
			}
			if !errors.Is(err, ErrConflict) || controller.registrations != 0 || controller.starts != 0 {
				t.Fatal("foreign preflight changed native service state", err)
			}
			if data != nil {
				if retained, err := os.ReadFile(filename); err != nil || !bytes.Equal(data, retained) {
					t.Fatal("foreign INI was changed", err)
				}
			} else if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("foreign preflight acquired a new INI", err)
			}
		})
	}
}

func TestLinuxActivationRunRetainsScopeAndRejectsPartialReadiness(t *testing.T) {
	for _, scenario := range []string{"amd64", "arm64", "readiness-conflict", "start-failed", "canceled-after-register", "wrong-platform", "missing-checkpoint", "unbound-image", "changed-after-proof"} {
		t.Run(scenario, func(t *testing.T) {
			nativeLinuxConfigurationFixture(t)
			o, d, store, image, _, _ := activationFixture(t)
			d.platform, store.identity.Platform = "linux", "linux"
			if scenario == "arm64" {
				d.architecture, store.identity.Architecture = "arm64", "arm64"
			}
			controller := &fakeLinuxController{}
			public, _ := store.identity.Keys.Broker.PublicKey()
			filename := filepath.Join(linuxservice.ConfigurationDirectory, "openuem.ini")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			controller.start = func(_ context.Context, identity localready.Identity, key string) error {
				if key != public || identity.DeviceID != fixtureDeviceID || identity.TenantID != 3 || identity.SiteID != 4 || identity.ReleaseDigest != store.identity.ReleaseDigest || identity.AgentSize != store.identity.AgentSize || identity.AgentSHA256 != store.identity.AgentSHA256 || !identity.ExpiresAt.Equal(store.identity.Response.ExpiresAt) {
					t.Error("run lost its stored enrollment binding")
				}
				switch scenario {
				case "readiness-conflict":
					return localready.ErrConflict
				case "start-failed":
					return linuxservice.ErrStart
				case "changed-after-proof":
					if err := os.WriteFile(filename, []byte("owned changed configuration"), 0600); err != nil {
						t.Error(err)
					}
				}
				return nil
			}
			d.prepare = func(ctx context.Context, executable, directory string, identity *enrollmentstore.Identity) (installation, error) {
				if executable != image.path || directory != o.IdentityDirectory || identity != store.identity {
					t.Error("activation changed retained inputs")
				}
				return prepareLinux(ctx, executable, directory, identity,
					func(context.Context, linuxservice.Spec) (linuxController, error) { return controller, nil },
					func(ctx context.Context, validate func([]byte) bool) (linuxConfiguration, error) {
						return linuxservice.OpenConfiguration(ctx, validate)
					})
			}
			switch scenario {
			case "canceled-after-register":
				controller.register = func(context.Context) error { controller.state = linuxservice.Enabled; cancel(); return nil }
			case "wrong-platform":
				store.identity.Platform = "windows"
			case "missing-checkpoint":
				store.checkpoint.Sequence = 0
			case "unbound-image":
				image.err = ErrAccess
			}
			result, err := run(ctx, o, d)
			switch scenario {
			case "amd64", "arm64":
				if err != nil || !result.Registered || !result.Running || result.DeviceID != fixtureDeviceID || result.TenantID != 3 || result.SiteID != 4 || result.ApprovalRequired {
					t.Fatal("Linux activation did not retain assigned scope", result, err)
				}
			case "wrong-platform", "missing-checkpoint", "unbound-image":
				if err == nil || result.Registered || result.Running || controller.registrations != 0 || controller.starts != 0 {
					t.Fatal("unadmitted enrollment reached Linux activation", result, err)
				}
				if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unadmitted enrollment published configuration", err)
				}
				return
			default:
				if err == nil || !result.Registered || result.Running || result.DeviceID != fixtureDeviceID || result.TenantID != 3 || result.SiteID != 4 {
					t.Fatal("partial Linux activation reported readiness or lost scope", result, err)
				}
			}
			if controller.closes != 1 || store.identity.Keys != nil {
				t.Fatal("run did not join its installation and identity resources")
			}
			if data, err := os.ReadFile(filename); err != nil || len(data) == 0 {
				t.Fatal("activation lost published configuration", err)
			}
		})
	}
}
