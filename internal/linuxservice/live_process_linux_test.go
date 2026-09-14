package linuxservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/openuem-agent/internal/localready"
)

type liveReadinessRecord struct {
	Identity localready.Identity
	Seed     []byte
	Mode     string
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		os.Exit(serveOwnedSystemdFixture())
	}
	os.Exit(m.Run())
}

// The canonical unit launches this helper only inside the marker-checked RAM
// guest. Its generated signing key never leaves that guest or enters logs.
func serveOwnedSystemdFixture() int {
	if len(os.Args) != 4 || os.Args[0] != "/fixture/linuxservice.test" || os.Args[2] != "-identity-directory" || os.Args[3] != "/fixture/identity" || ownedSystemdGuest() != nil {
		return 1
	}
	data, err := os.ReadFile("/fixture/identity/helper.json")
	if err != nil || len(data) > 4096 {
		return 1
	}
	var record liveReadinessRecord
	if json.Unmarshal(data, &record) != nil {
		return 1
	}
	defer clear(data)
	defer clear(record.Seed)
	key, err := nkeys.FromSeed(record.Seed)
	if err != nil {
		return 1
	}
	defer key.Wipe()
	if record.Mode == "wrong-identity" {
		record.Identity.SiteID++
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	server, err := localready.Listen(ctx, "/fixture/identity", record.Identity, key)
	if err != nil {
		return 1
	}
	defer server.Close()
	if record.Mode != "not-ready" {
		if server.MarkReady() != nil {
			return 1
		}
	}
	<-ctx.Done()
	if server.Close() != nil {
		return 1
	}
	return 0
}

func serviceIdentityFixture() localready.Identity {
	return localready.Identity{DeviceID: "573d2610-9f96-40b5-a63e-226ab2f45171", TenantID: 1, SiteID: 2,
		ReleaseDigest: strings.Repeat("a", 64), AgentSize: 1024, AgentSHA256: strings.Repeat("b", 64),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
}

func TestLinuxLiveSystemdServiceStart(t *testing.T) {
	liveSystemdFixture(t)
	for _, scenario := range []string{"fresh", "already-running", "not-ready", "wrong-identity"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			spec := Spec{Executable: "/fixture/linuxservice.test", IdentityDirectory: "/fixture/identity"}
			if err := os.Mkdir(spec.IdentityDirectory, 0700); err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(spec.IdentityDirectory)
			key, err := nkeys.CreateUser()
			if err != nil {
				t.Fatal(err)
			}
			defer key.Wipe()
			public, _ := key.PublicKey()
			seed, _ := key.Seed()
			defer clear(seed)
			identity := serviceIdentityFixture()
			data, err := json.Marshal(liveReadinessRecord{Identity: identity, Seed: seed, Mode: scenario})
			if err != nil || os.WriteFile(spec.IdentityDirectory+"/helper.json", data, 0600) != nil {
				t.Fatal("could not publish owned helper input")
			}
			clear(data)
			defer cleanupLiveStartedService(t, spec)
			s, err := Open(ctx, spec)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.Register(ctx); err != nil {
				t.Fatal(err)
			}
			startCtx := ctx
			if scenario == "not-ready" {
				var cancelStart context.CancelFunc
				startCtx, cancelStart = context.WithTimeout(ctx, 1500*time.Millisecond)
				defer cancelStart()
			}
			err = s.Start(startCtx, identity, public)
			switch scenario {
			case "not-ready":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("initializing actual service did not wait for readiness", err)
				}
			case "wrong-identity":
				if !errors.Is(err, localready.ErrConflict) {
					t.Fatal("foreign signed identity was not rejected", err)
				}
			default:
				if err != nil {
					logLiveProcessState(t, s.connection, ctx)
					t.Fatal("actual service did not prove readiness", err)
				}
			}
			if scenario == "not-ready" {
				// Canceling an in-flight manager call invalidates its connection.
				// Verify retained service state through a fresh admitted owner.
				s.Close()
				s, err = Open(ctx, spec)
				if err != nil {
					t.Fatal("canceled start could not reopen retained registration", err)
				}
				defer s.Close()
			}
			definition, err := s.connection.loadDefinition(ctx, spec)
			if err != nil || definition.State.Active != "active" || definition.State.PID == 0 {
				t.Fatal("owned helper was not running", err)
			}
			before := definition.State
			if scenario == "already-running" {
				if err := s.Start(ctx, identity, public); err != nil {
					t.Fatal("already running service could not be admitted", err)
				}
			}
			s.Close()
			s, err = Open(ctx, spec)
			if err != nil {
				t.Fatal("retained service could not be reopened", err)
			}
			defer s.Close()
			definition, err = s.connection.loadDefinition(ctx, spec)
			if err != nil || definition.State != before {
				t.Fatal("retry, failure or close changed the running invocation", err)
			}
		})
	}
}

func logLiveProcessState(t *testing.T, c *systemdConnection, ctx context.Context) {
	t.Helper()
	for _, iface := range []string{"Unit", "Service"} {
		body, err := c.call(ctx, unitObjectPath, "org.freedesktop.DBus.Properties.GetAll", "org.freedesktop.systemd1."+iface)
		if err != nil || len(body) != 1 {
			t.Log("owned process properties unavailable", err)
			continue
		}
		values, ok := body[0].(map[string]dbus.Variant)
		if !ok {
			continue
		}
		for _, name := range []string{"LoadState", "UnitFileState", "Names", "DropInPaths", "InvocationID", "NeedDaemonReload", "ActiveState", "SubState", "Job", "StateChangeTimestampMonotonic", "MainPID", "ExecMainPID", "ExecMainStartTimestampMonotonic", "ExecStartEx"} {
			if value, ok := values[name]; ok {
				t.Logf("owned process %s.%s: %v", iface, name, value)
			}
		}
	}
}

func cleanupLiveStartedService(t *testing.T, spec Spec) {
	t.Helper()
	if err := ownedSystemdGuest(); err != nil {
		t.Error(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := Open(ctx, spec)
	if err != nil {
		t.Error("cannot admit owned process cleanup", err)
		return
	}
	defer s.Close()
	observation, err := s.observe(ctx)
	if err != nil || observation.status() != Enabled {
		t.Error("owned process cleanup lacks registration evidence", err)
		return
	}
	// Stopping is exclusively a test cleanup operation after fresh admission
	// inside the isolated guest. The production controller has no Stop method.
	if _, err := s.connection.call(ctx, managerPath, managerInterface+".StopUnit", UnitName, "fail"); err != nil {
		t.Error("owned helper stop failed", err)
		return
	}
	for {
		observation, err := s.observe(ctx)
		if err == nil && observation.definition.State.Active == "inactive" && observation.definition.State.PID == 0 && observation.definition.State.JobID == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Error("owned helper did not join shutdown")
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
	s.Close()
	cleanupLiveRegistration(t, spec)
}
