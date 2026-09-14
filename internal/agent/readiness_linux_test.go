package agent

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/openuem-agent/internal/localready"
	"golang.org/x/sys/unix"
)

func TestLinuxSchedulerPublishesNativeReadinessAfterInitialization(t *testing.T) {
	if os.Getenv("OPENUEM_TEST_LINUX_READINESS") != "owned-isolated-readiness" {
		t.Skip("requires isolated root Linux readiness fixture")
	}
	var fs unix.Statfs_t
	if os.Geteuid() != 0 || os.TempDir() != "/fixture" || unix.Statfs("/fixture", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Fatal("native readiness requires owned private tmpfs")
	}
	path, err := os.MkdirTemp("/fixture", "agent-ready-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(path)
	a := readinessAgent(t)
	defer a.Stop()
	a.individual.directory = path
	i := a.individual.identity
	identity := localready.Identity{DeviceID: i.Response.DeviceID, TenantID: i.Response.TenantID, SiteID: i.Response.SiteID, ReleaseDigest: i.ReleaseDigest, AgentSize: i.AgentSize, AgentSHA256: i.AgentSHA256, ExpiresAt: i.Response.ExpiresAt}
	public, err := i.Keys.Broker.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	started := false
	a.TaskScheduler = &readinessScheduler{start: func() {
		started = true
		if err := localready.Probe(context.Background(), path, identity, public); !errors.Is(err, localready.ErrNotReady) {
			t.Error("Linux readiness preceded scheduler initialization", err)
		}
	}}
	err = a.startInitializedScheduler(func(ctx context.Context, directory string, identity localready.Identity, signer nkeys.KeyPair) (readinessEndpoint, error) {
		return localready.Listen(ctx, directory, identity, signer)
	})
	if err != nil || !started {
		t.Fatal("Linux scheduler did not initialize with owned readiness", err)
	}
	if err = localready.Probe(context.Background(), path, identity, public); err != nil {
		t.Fatal("initialized Linux runtime did not authenticate readiness", err)
	}
	a.Stop()
	if err = localready.Probe(context.Background(), path, identity, public); err == nil {
		t.Fatal("stopped Linux runtime retained readiness")
	}
}
