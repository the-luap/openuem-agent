package activatecommand

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-uem/openuem-agent/internal/linuxservice"
	"github.com/open-uem/openuem-agent/internal/localready"
	"golang.org/x/sys/unix"
)

func liveActivationGuest(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENUEM_TEST_LIVE_SYSTEMD") != "owned-virtual-machine" {
		t.Skip("requires the owned virtual systemd machine")
	}
	if err := ownedActivationGuest(); err != nil {
		t.Fatal(err)
	}
}

func ownedActivationGuest() error {
	marker, err := os.ReadFile("/etc/openuem-systemd-fixture")
	if err != nil || string(marker) != "owned-virtual-machine\n" {
		return errors.New("missing owned guest marker")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !bytes.Contains(cmdline, []byte("openuem_fixture=owned-virtual-machine")) {
		return errors.New("missing owned kernel marker")
	}
	manager, err := os.ReadFile("/proc/1/comm")
	var fs unix.Statfs_t
	if err != nil || string(manager) != "systemd\n" || os.Geteuid() != 0 || unix.Statfs("/", &fs) != nil || (fs.Type != unix.RAMFS_MAGIC && fs.Type != unix.TMPFS_MAGIC) {
		return errors.New("activation requires the owned RAM-only root system manager")
	}
	return nil
}

func TestLinuxLiveActivationProviders(t *testing.T) {
	liveActivationGuest(t)
	for _, scenario := range []string{"fresh", "retained-settings", "not-ready", "wrong-identity"} {
		if !t.Run(scenario, func(t *testing.T) { checkLiveActivationProviders(t, scenario) }) {
			return
		}
	}
}

func checkLiveActivationProviders(t *testing.T, scenario string) {
	t.Helper()
	const executable, directory = "/fixture/linuxservice.test", "/fixture/identity"
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	_, _, store, _, _, _ := activationFixture(t)
	identity := store.identity
	identity.Platform = "linux"
	identity.Response.ExpiresAt = time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	image, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, image)
	image.Close()
	if err != nil || size <= 0 {
		t.Fatal("owned helper image could not be bound", err)
	}
	identity.AgentSize, identity.AgentSHA256 = size, hex.EncodeToString(hash.Sum(nil))
	ready := localready.Identity{DeviceID: identity.Response.DeviceID, TenantID: identity.Response.TenantID, SiteID: identity.Response.SiteID,
		ReleaseDigest: identity.ReleaseDigest, AgentSize: size, AgentSHA256: identity.AgentSHA256, ExpiresAt: identity.Response.ExpiresAt}
	public, err := identity.Keys.Broker.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := identity.Keys.Broker.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	// Cleanup runs after any registered helper has joined shutdown below. All
	// these paths exist only in this fresh, marker-checked RAM guest.
	defer os.RemoveAll(directory)
	defer os.RemoveAll(linuxservice.ConfigurationDirectory)
	defer os.RemoveAll(linuxservice.LogDirectory)
	record, err := json.Marshal(struct {
		Identity localready.Identity
		Seed     []byte
		Mode     string
	}{ready, seed, scenario})
	if err != nil || os.WriteFile(directory+"/helper.json", record, 0600) != nil {
		t.Fatal("could not prepare owned helper identity")
	}
	clear(record)
	filename := filepath.Join(linuxservice.ConfigurationDirectory, "openuem.ini")
	var expected []byte
	if scenario == "retained-settings" {
		if os.Mkdir(linuxservice.ConfigurationDirectory, 0700) != nil || os.Mkdir(linuxservice.LogDirectory, 0700) != nil {
			t.Fatal("could not prepare owned operational directories")
		}
		expected = bytes.ReplaceAll(configuration(identity), []byte("DefaultFrequency = 15"), []byte("DefaultFrequency = 20"))
		if os.WriteFile(filename, expected, 0600) != nil || os.WriteFile(filepath.Join(linuxservice.LogDirectory, "openuem-agent.log"), []byte("owned retained log"), 0600) != nil {
			t.Fatal("could not prepare owned operational settings")
		}
	}
	p, err := prepareNative(ctx, executable, directory, identity)
	if err != nil {
		t.Fatal("actual activation preflight failed", err)
	}
	defer p.Close()
	if scenario != "retained-settings" {
		if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("activation preflight published configuration", err)
		}
	}
	if err := p.PrepareConfiguration(ctx); err != nil {
		t.Fatal("actual configuration preparation failed", err)
	}
	if err := p.Register(ctx); err != nil {
		t.Fatal("actual activation registration failed", err)
	}
	defer func() {
		p.Close()
		cleanupCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		// The cleanup entry point lives with the native manager fixture and
		// re-admits this exact unit before stopping it. No host service is used.
		command := exec.CommandContext(cleanupCtx, executable, "-test.v", "-test.count=1", "-test.timeout=10s", "-test.run=^TestLinuxOwnedActivationCleanup$")
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("owned activation cleanup failed: %v\n%s", err, output)
		} else if !bytes.Contains(output, []byte("--- PASS: TestLinuxOwnedActivationCleanup")) {
			t.Error("owned activation cleanup did not execute")
		}
	}()
	var before unix.Stat_t
	if unix.Lstat(filename, &before) != nil {
		t.Fatal("prepared INI disappeared")
	}
	startCtx := ctx
	if scenario == "not-ready" {
		var stop context.CancelFunc
		startCtx, stop = context.WithTimeout(ctx, 1500*time.Millisecond)
		defer stop()
	}
	err = p.Start(startCtx)
	switch scenario {
	case "not-ready":
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("initializing service was reported as ready", err)
		}
	case "wrong-identity":
		if !errors.Is(err, ErrConflict) {
			t.Fatal("foreign signed identity was admitted", err)
		}
	default:
		if err != nil {
			t.Fatal("actual native activation did not prove readiness", err)
		}
	}
	if registered, approval := p.(interface{ RegistrationResult() (bool, bool) }).RegistrationResult(); !registered || approval {
		t.Fatal("activation lost registered state")
	}
	p.Close()
	if scenario == "fresh" || scenario == "retained-settings" {
		if err := localready.Probe(ctx, directory, ready, public); err != nil {
			t.Fatal("closing activation stopped the ready service", err)
		}
	}
	p, err = prepareNative(ctx, executable, directory, identity)
	if err != nil {
		t.Fatal("retained native activation could not be reopened", err)
	}
	defer p.Close()
	if err := p.PrepareConfiguration(ctx); err != nil {
		t.Fatal("retained operational settings were rejected", err)
	}
	if err := p.Register(ctx); err != nil {
		t.Fatal("retained registration was rejected", err)
	}
	if scenario == "fresh" || scenario == "retained-settings" {
		if err := p.Start(ctx); err != nil {
			t.Fatal("already running activation did not verify", err)
		}
		if err := localready.Probe(ctx, directory, ready, public); err != nil {
			t.Fatal("controller close lost the ready service", err)
		}
	}
	data, err := os.ReadFile(filename)
	var after unix.Stat_t
	if err != nil || !validConfiguration(data, identity) || unix.Lstat(filename, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatal("activation replaced its operational INI", err)
	}
	if expected != nil && !bytes.Equal(data, expected) {
		t.Fatal("actual activation rewrote administrator settings")
	}
	if scenario == "retained-settings" {
		if data, err := os.ReadFile(filepath.Join(linuxservice.LogDirectory, "openuem-agent.log")); err != nil || string(data) != "owned retained log" {
			t.Fatal("activation modified existing log evidence", err)
		}
	}
}
