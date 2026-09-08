package activatecommand

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/localready"
	"github.com/open-uem/openuem-agent/internal/macservice"
)

type fakeMacController struct {
	state                 macservice.Status
	register              func(context.Context) (macservice.Status, error)
	registrations, closes int
}

func (c *fakeMacController) Status(context.Context) (macservice.Status, error) { return c.state, nil }
func (c *fakeMacController) Register(ctx context.Context) (macservice.Status, error) {
	c.registrations++
	if c.register != nil {
		return c.register(ctx)
	}
	c.state = macservice.Enabled
	return c.state, nil
}
func (c *fakeMacController) Close() error { c.closes++; return nil }

func macFixture(t *testing.T) (Options, dependencies, *fakeStore, *fakeMacController, macSettings, *int) {
	t.Helper()
	o, d, store, image, _, events := activationFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	settings := macSettings{base: filepath.Join(root, "agent"), logs: filepath.Join(root, "logs"), uid: uint32(os.Geteuid()), ancestors: []string{root}}
	o.IdentityDirectory = filepath.Join(settings.base, "identity")
	for _, path := range []string{settings.base, o.IdentityDirectory} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	d.platform, store.identity.Platform = "darwin", "macos"
	controller := &fakeMacController{state: macservice.NotRegistered}
	probes := new(int)
	d.openStore = func(path string) (identityStore, error) {
		if path != o.IdentityDirectory {
			t.Error("identity directory changed")
		}
		*events = append(*events, "store-open")
		return store, nil
	}
	d.prepare = func(ctx context.Context, path, directory string, identity *enrollmentstore.Identity) (installation, error) {
		if path != image.path || directory != o.IdentityDirectory || identity != store.identity {
			t.Error("protected activation inputs changed")
		}
		return prepareMac(ctx, path, directory, identity, settings, func(context.Context, string) (macController, error) { return controller, nil }, func(ctx context.Context, directory string, got localready.Identity, public string) error {
			*probes++
			wantPublic, err := identity.Keys.Broker.PublicKey()
			if err != nil || public != wantPublic || directory != o.IdentityDirectory || got.DeviceID != identity.Response.DeviceID || got.TenantID != identity.Response.TenantID || got.SiteID != identity.Response.SiteID || got.ReleaseDigest != identity.ReleaseDigest || got.AgentSize != identity.AgentSize || got.AgentSHA256 != identity.AgentSHA256 || !got.ExpiresAt.Equal(identity.Response.ExpiresAt) {
				t.Error("probe lost its protected identity binding")
			}
			return ctx.Err()
		})
	}
	return o, d, store, controller, settings, probes
}

func TestMacActivationRequiresApprovalAndPreservesCanceledRegistration(t *testing.T) {
	for _, scenario := range []string{"ready", "approval", "canceled-after-registration", "registration-failed", "proof-conflict", "proof-unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			o, d, store, controller, settings, probes := macFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			switch scenario {
			case "approval", "canceled-after-registration":
				controller.register = func(context.Context) (macservice.Status, error) {
					controller.state = macservice.RequiresApproval
					if scenario == "canceled-after-registration" {
						cancel()
						return controller.state, context.Canceled
					}
					return controller.state, nil
				}
			case "registration-failed":
				controller.register = func(context.Context) (macservice.Status, error) {
					return macservice.NotRegistered, macservice.ErrRegistration
				}
			case "proof-conflict", "proof-unavailable":
				prepare := d.prepare
				d.prepare = func(ctx context.Context, path, directory string, identity *enrollmentstore.Identity) (installation, error) {
					p, err := prepare(ctx, path, directory, identity)
					if err == nil {
						p.(*macInstallation).probe = func(context.Context, string, localready.Identity, string) error {
							*probes++
							if scenario == "proof-conflict" {
								return localready.ErrConflict
							}
							return localready.ErrUnavailable
						}
					}
					return p, err
				}
			}
			result, err := run(ctx, o, d)
			if result.Registered != (scenario != "registration-failed") || result.Running != (scenario == "ready") || result.ApprovalRequired != (scenario == "approval" || scenario == "canceled-after-registration") {
				t.Fatal("activation overstated native state", result, err)
			}
			want := map[string]error{"approval": ErrApproval, "canceled-after-registration": context.Canceled, "registration-failed": ErrRegistration, "proof-conflict": ErrConflict, "proof-unavailable": context.DeadlineExceeded}[scenario]
			if !errors.Is(err, want) {
				t.Fatal("unexpected activation error", err, want)
			}
			if controller.closes != 1 || store.identity.Keys != nil {
				t.Fatal("activation retained its resources")
			}
			if (scenario == "approval" || scenario == "canceled-after-registration" || scenario == "registration-failed") && *probes != 0 {
				t.Fatal("an ineligible service was probed")
			}
			data, err := readMacConfiguration(filepath.Join(settings.base, "etc/openuem-agent/openuem.ini"), settings.uid)
			if err != nil || !validConfiguration(data, store.identity) {
				t.Fatal("activation did not retain protected configuration", err)
			}
		})
	}
}

func TestMacApprovalRetryPreservesOperationalSettings(t *testing.T) {
	o, d, store, controller, settings, _ := macFixture(t)
	controller.register = func(context.Context) (macservice.Status, error) { return controller.state, nil }
	controller.state = macservice.RequiresApproval
	image, err := d.openExecutable()
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	path, err := image.InstalledPath()
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.prepare(context.Background(), path, o.IdentityDirectory, store.identity)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.PrepareConfiguration(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background()); !errors.Is(err, ErrApproval) {
		t.Fatal(err)
	}
	configPath := filepath.Join(settings.base, "etc/openuem-agent/openuem.ini")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte("Enabled = true"), []byte("Enabled = false"), 1)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	controller.state = macservice.Enabled
	if err := p.PrepareConfiguration(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("approval retry replaced operational settings", err)
	}
}

func TestMacActivationPreservesForeignConfigurationLogsAndUnsafeDirectories(t *testing.T) {
	for _, scenario := range []string{"foreign-config", "foreign-log", "public-directory", "config-symlink", "config-hardlink"} {
		t.Run(scenario, func(t *testing.T) {
			o, d, _, controller, settings, _ := macFixture(t)
			configDir := filepath.Join(settings.base, "etc/openuem-agent")
			for _, path := range []string{filepath.Join(settings.base, "etc"), configDir, settings.logs} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(configDir, "openuem.ini")
			foreign := []byte("preserve this foreign installation")
			if scenario == "foreign-log" {
				path = filepath.Join(settings.logs, "openuem-agent.log")
			}
			if err := os.WriteFile(path, foreign, 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "public-directory":
				if err := os.Chmod(configDir, 0755); err != nil {
					t.Fatal(err)
				}
			case "config-symlink":
				if err := os.Rename(path, path+".foreign"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".foreign", path); err != nil {
					t.Fatal(err)
				}
			case "config-hardlink":
				if err := os.Link(path, path+".foreign"); err != nil {
					t.Fatal(err)
				}
			}
			result, err := run(context.Background(), o, d)
			if !errors.Is(err, ErrConflict) || result.Registered || controller.registrations != 0 {
				t.Fatal("foreign installation reached registration", result, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(foreign, after) {
				t.Fatal("foreign data changed", err)
			}
		})
	}
}

func TestMacConfigurationPublicationPreservesOneConcurrentWinner(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "openuem.ini")
	results := make(chan error, 2)
	var work sync.WaitGroup
	for _, data := range [][]byte{[]byte("first complete fixture"), []byte("second complete fixture")} {
		work.Go(func() { results <- publishMacConfiguration(path, data, uint32(os.Geteuid())) })
	}
	work.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("publication did not retain one winner")
	}
	data, err := readMacConfiguration(path, uint32(os.Geteuid()))
	if err != nil || (string(data) != "first complete fixture" && string(data) != "second complete fixture") {
		t.Fatal("publication left partial or linked temporary state", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("publication retained a temporary file", err)
	}
}
