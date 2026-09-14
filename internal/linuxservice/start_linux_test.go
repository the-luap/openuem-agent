package linuxservice

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/openuem-agent/internal/localready"
)

type startPeer struct {
	peer             *managerFixturePeer
	starts           atomic.Uint32
	unitReads        atomic.Uint32
	running, changed atomic.Bool
	entered, release chan struct{}
}

func newStartPeer(t *testing.T, filename string, spec Spec, scenario string) *startPeer {
	t.Helper()
	data, _ := Render(spec)
	if err := os.WriteFile(filename, data, 0644); err != nil {
		t.Fatal(err)
	}
	wants := filepath.Join(filepath.Dir(filename), wantsDirectory)
	if os.Mkdir(wants, 0755) != nil || os.Symlink(UnitPath, filepath.Join(wants, UnitName)) != nil {
		t.Fatal("could not prepare owned enablement")
	}
	p := &startPeer{entered: make(chan struct{}), release: make(chan struct{})}
	p.running.Store(scenario == "already-running")
	p.peer = newManagerPeer(t, managerFixture(t), func(wire *net.UnixConn) error {
		r, err := authenticateManagerPeer(wire, false)
		if err != nil {
			return err
		}
		for {
			call, err := dbus.DecodeMessage(r)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			if call.Type != dbus.TypeMethodCall {
				return errors.New("start emitted a non-method message")
			}
			object, iface, member := call.Headers[dbus.FieldPath].Value(), call.Headers[dbus.FieldInterface].Value(), call.Headers[dbus.FieldMember].Value()
			var body []any
			switch {
			case object == managerPath && iface == managerInterface && member == "LoadUnit":
				if len(call.Body) != 1 || call.Body[0] != UnitName {
					return errors.New("start loaded another unit")
				}
				body = []any{unitObjectPath}
			case object == unitObjectPath && iface == "org.freedesktop.DBus.Properties" && member == "GetAll":
				if len(call.Body) != 1 || (call.Body[0] != "org.freedesktop.systemd1.Unit" && call.Body[0] != "org.freedesktop.systemd1.Service") {
					return errors.New("start queried an unexpected interface")
				}
				_, unit, service := stateFixture()
				pid, started, invoked := uint32(0), uint64(0), []byte{}
				active, substate := "inactive", "dead"
				if p.running.Load() {
					pid, started, invoked = uint32(os.Getpid()), 200, make([]byte, 16)
					invoked[0] = 1
					active, substate = "active", "running"
					if scenario == "starting-transition" && call.Body[0] == "org.freedesktop.systemd1.Unit" && p.unitReads.Add(1) == 1 {
						active, substate = "activating", "start"
					}
					if scenario == "foreign-start-definition" {
						unit["DropInPaths"] = dbus.MakeVariant([]string{"/owned-foreign.conf"})
					}
					if scenario == "wrong-pid" {
						pid++
					}
				}
				commandStarted := started
				if p.changed.Load() {
					switch scenario {
					case "changed-pid":
						pid++
					case "changed-start":
						started++
					case "changed-command-start":
						commandStarted--
					case "changed-invocation", "initializing-restart":
						invoked[0]++
					case "changed-job":
						unit["Job"] = dbus.MakeVariant(unitJob{ID: 43, Path: "/org/freedesktop/systemd1/job/43"})
					case "changed-enablement":
						unit["UnitFileState"] = dbus.MakeVariant("disabled")
					case "changed-definition":
						unit["DropInPaths"] = dbus.MakeVariant([]string{"/owned-foreign.conf"})
					}
				}
				if scenario == "pending-job" {
					unit["Job"] = dbus.MakeVariant(unitJob{ID: 42, Path: "/org/freedesktop/systemd1/job/42"})
				}
				if scenario == "deactivating" {
					active, substate = "deactivating", "stop"
				}
				if scenario == "auto-restart" {
					active, substate = "activating", "auto-restart"
				}
				unit["ActiveState"], unit["SubState"], unit["InvocationID"] = dbus.MakeVariant(active), dbus.MakeVariant(substate), dbus.MakeVariant(invoked)
				service["MainPID"], service["ExecMainPID"], service["ExecMainStartTimestampMonotonic"] = dbus.MakeVariant(pid), dbus.MakeVariant(pid), dbus.MakeVariant(started)
				service["ExecStartEx"] = dbus.MakeVariant([]execCommand{{Path: spec.Executable, Args: []string{spec.Executable, "serve", "-identity-directory", spec.IdentityDirectory}, Flags: []string{"no-env-expand"}, StartMonotonic: commandStarted, PID: pid}})
				properties := unit
				if call.Body[0] == "org.freedesktop.systemd1.Service" {
					properties = service
				}
				body = []any{properties}
			case object == managerPath && iface == managerInterface && member == "StartUnit":
				if len(call.Body) != 2 || call.Body[0] != UnitName || call.Body[1] != "fail" {
					return errors.New("start changed another unit or replaced a pending job")
				}
				p.starts.Add(1)
				p.running.Store(true)
				if scenario == "blocked-start" {
					close(p.entered)
					<-p.release
					return nil
				}
				if scenario == "start-error" {
					if err := sendManagerReply(wire, call, "org.freedesktop.DBus.Error.Failed", "synthetic-sensitive-start"); err != nil {
						return err
					}
					continue
				}
				body = []any{dbus.ObjectPath("/org/freedesktop/systemd1/job/42")}
				if scenario == "malformed-job" {
					body = []any{dbus.ObjectPath("/org/freedesktop/systemd1/job/042")}
				}
			default:
				return errors.New("start emitted an unauthorized mutating method")
			}
			if err := sendManagerReply(wire, call, "", body...); err != nil {
				return err
			}
		}
	})
	return p
}

func (p *startPeer) connect(ctx context.Context) (*systemdConnection, error) {
	return connectPrivateManager(ctx, p.peer.path, int32(os.Getpid()))
}

func TestLinuxStartRequiresStableSignedProcessReadiness(t *testing.T) {
	for _, scenario := range []string{"fresh", "already-running", "becomes-ready", "starting-transition", "foreign-start-definition", "wrong-pid", "wrong-identity", "wrong-key", "changed-pid", "changed-start", "changed-command-start", "changed-invocation", "changed-job", "changed-enablement", "changed-definition", "changed-file", "changed-link", "initializing-restart", "pending-job", "deactivating", "auto-restart", "start-error", "malformed-job"} {
		t.Run(scenario, func(t *testing.T) {
			filename, spec, _ := unitFileFixture(t)
			spec.IdentityDirectory = managerFixture(t)
			p := newStartPeer(t, filename, spec, scenario)
			s, err := openServiceAt(t.Context(), spec, filename, p.connect)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			key, err := nkeys.CreateUser()
			if err != nil {
				t.Fatal(err)
			}
			defer key.Wipe()
			public, _ := key.PublicKey()
			identity := serviceIdentityFixture()
			served := identity
			if scenario == "wrong-identity" {
				served.SiteID++
			}
			if scenario == "wrong-key" {
				other, _ := nkeys.CreateUser()
				defer other.Wipe()
				public, _ = other.PublicKey()
			}
			server, err := localready.Listen(t.Context(), spec.IdentityDirectory, served, key)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if scenario != "becomes-ready" && scenario != "initializing-restart" {
				if err := server.MarkReady(); err != nil {
					t.Fatal(err)
				}
			}
			probes := 0
			probe := func(ctx context.Context, directory string, id localready.Identity, pub string, pid uint32) error {
				probes++
				err := localready.ProbeProcess(ctx, directory, id, pub, pid)
				p.changed.Store(true)
				if scenario == "becomes-ready" {
					if e := server.MarkReady(); e != nil {
						return e
					}
				}
				if scenario == "changed-file" {
					if e := os.WriteFile(filename, []byte("owned changed definition"), 0644); e != nil {
						return e
					}
				}
				if scenario == "changed-link" {
					if e := os.Remove(filepath.Join(filepath.Dir(filename), wantsDirectory, UnitName)); e != nil {
						return e
					}
				}
				return err
			}
			err = s.start(t.Context(), identity, public, probe)
			if slices.Contains([]string{"fresh", "already-running", "becomes-ready", "starting-transition"}, scenario) {
				if err != nil {
					t.Fatal("matching native signed readiness was rejected", err)
				}
				if scenario == "becomes-ready" && probes != 2 {
					t.Fatal("initialization did not require another signed probe", probes)
				}
				if err := s.Start(t.Context(), identity, public); err != nil {
					t.Fatal("running retry failed", err)
				}
			} else if err == nil || strings.Contains(err.Error(), "synthetic-sensitive") {
				t.Fatal("incomplete or replaced start succeeded or exposed peer data", err)
			}
			wantStarts := uint32(1)
			if slices.Contains([]string{"already-running", "pending-job", "deactivating", "auto-restart"}, scenario) {
				wantStarts = 0
			}
			if p.starts.Load() != wantStarts {
				t.Fatal("unexpected repeated or unauthorized start", p.starts.Load())
			}
			if slices.Contains([]string{"wrong-pid", "wrong-identity", "wrong-key"}, scenario) && !errors.Is(err, localready.ErrConflict) {
				t.Fatal("readiness identity conflict not preserved", err)
			}
			s.Close()
			data, err := os.ReadFile(filename)
			if err != nil || (scenario != "changed-file" && !Matches(data, spec)) || (scenario == "changed-file" && string(data) != "owned changed definition") {
				t.Fatal("start or close changed persistent evidence", err)
			}
		})
	}
}

func TestLinuxStartCancellationJoinsManagerAndReadiness(t *testing.T) {
	for _, scenario := range []string{"canceled", "invalid-identity", "invalid-key", "blocked-start", "blocked-probe"} {
		t.Run(scenario, func(t *testing.T) {
			filename, spec, _ := unitFileFixture(t)
			p := newStartPeer(t, filename, spec, scenario)
			defer close(p.release)
			s, err := openServiceAt(t.Context(), spec, filename, p.connect)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			key, _ := nkeys.CreateUser()
			defer key.Wipe()
			public, _ := key.PublicKey()
			identity := serviceIdentityFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "canceled" {
				cancel()
			}
			if scenario == "invalid-identity" {
				identity.ExpiresAt = time.Time{}
			}
			if scenario == "invalid-key" {
				public = "invalid"
			}
			probe := func(ctx context.Context, _ string, _ localready.Identity, _ string, _ uint32) error {
				close(p.entered)
				<-ctx.Done()
				return ctx.Err()
			}
			done := make(chan error, 1)
			go func() { done <- s.start(ctx, identity, public, probe) }()
			if strings.HasPrefix(scenario, "blocked-") {
				select {
				case <-p.entered:
				case <-time.After(time.Second):
					t.Fatal("start did not reach the held operation")
				}
				closed := make(chan struct{})
				go func() { s.Close(); close(closed) }()
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("close did not cancel and join the held start")
				}
			} else if p.starts.Load() != 0 {
				t.Fatal("invalid input started a service")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("interrupted or invalid start reported readiness")
				}
			case <-time.After(time.Second):
				t.Fatal("start did not return")
			}
			if !strings.HasPrefix(scenario, "blocked-") && p.starts.Load() != 0 {
				t.Fatal("rejected input started a service")
			}
			if data, err := os.ReadFile(filename); err != nil || !Matches(data, spec) {
				t.Fatal("canceled start removed the unit", err)
			}
		})
	}
}

func TestLinuxStartJobRequiresCanonicalTypedIdentity(t *testing.T) {
	for _, body := range [][]any{nil, {"/org/freedesktop/systemd1/job/42"}, {dbus.ObjectPath("/")}, {dbus.ObjectPath("/org/freedesktop/systemd1/job/0")}, {dbus.ObjectPath("/org/freedesktop/systemd1/job/01")}, {dbus.ObjectPath("/org/freedesktop/systemd1/job/4294967296")}, {dbus.ObjectPath("/org/freedesktop/systemd1/job/42"), uint32(42)}} {
		if _, err := startJob(body); !errors.Is(err, ErrStart) {
			t.Fatal("malformed start job admitted")
		}
	}
	if id, err := startJob([]any{dbus.ObjectPath("/org/freedesktop/systemd1/job/4294967295")}); err != nil || id != ^uint32(0) {
		t.Fatal("canonical job rejected", err)
	}
}
