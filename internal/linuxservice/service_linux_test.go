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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

type registrationPeer struct {
	peer             *managerFixturePeer
	reloads, enables atomic.Uint32
	entered, release chan struct{}
}

type fixtureUnitFileChange struct{ Type, Path, Source string }

func newRegistrationPeer(t *testing.T, filename string, spec Spec, scenario string) *registrationPeer {
	t.Helper()
	p := &registrationPeer{entered: make(chan struct{}), release: make(chan struct{})}
	registered := scenario == "already-enabled" || scenario == "unowned-enablement"
	link := filepath.Join(filepath.Dir(filename), wantsDirectory, UnitName)
	createLink := func(target string) error {
		if err := os.Mkdir(filepath.Dir(link), 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		return os.Symlink(target, link)
	}
	if slices.Contains([]string{"prepared", "pending-reload", "already-enabled", "unowned-enablement"}, scenario) {
		data, _ := Render(spec)
		if err := os.WriteFile(filename, data, 0644); err != nil {
			t.Fatal(err)
		}
		if scenario == "already-enabled" {
			if err := createLink(UnitPath); err != nil {
				t.Fatal(err)
			}
		}
	}
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
				return errors.New("registration emitted a non-method message")
			}
			object, iface, member := call.Headers[dbus.FieldPath].Value(), call.Headers[dbus.FieldInterface].Value(), call.Headers[dbus.FieldMember].Value()
			var body []any
			switch {
			case object == managerPath && iface == managerInterface && member == "LoadUnit":
				if len(call.Body) != 1 || call.Body[0] != UnitName {
					return errors.New("registration loaded another unit")
				}
				body = []any{unitObjectPath}
			case object == unitObjectPath && iface == "org.freedesktop.DBus.Properties" && member == "GetAll":
				if len(call.Body) != 1 || (call.Body[0] != "org.freedesktop.systemd1.Unit" && call.Body[0] != "org.freedesktop.systemd1.Service") {
					return errors.New("registration queried an unexpected property interface")
				}
				_, fileErr := os.Lstat(filename)
				unit, service := absentDefinitionFixture()
				if (fileErr == nil && !(scenario == "pending-reload" && p.reloads.Load() == 0)) || scenario == "vendor" || scenario == "orphan-loaded" {
					_, unit, service = stateFixture()
					unit["UnitFileState"] = dbus.MakeVariant("disabled")
					if registered && scenario != "post-enable-disabled" {
						unit["UnitFileState"] = dbus.MakeVariant("enabled")
					}
					unit["ActiveState"], unit["SubState"] = dbus.MakeVariant("inactive"), dbus.MakeVariant("dead")
					unit["InvocationID"] = dbus.MakeVariant([]byte{})
					service["MainPID"], service["ExecMainPID"] = dbus.MakeVariant(uint32(0)), dbus.MakeVariant(uint32(0))
					service["ExecMainStartTimestampMonotonic"] = dbus.MakeVariant(uint64(0))
					service["ExecStartEx"] = dbus.MakeVariant([]execCommand{{Path: spec.Executable, Args: []string{spec.Executable, "serve", "-identity-directory", spec.IdentityDirectory}, Flags: []string{"no-env-expand"}}})
				}
				if scenario == "vendor" {
					unit["FragmentPath"] = dbus.MakeVariant("/usr/lib/systemd/system/" + UnitName)
				}
				if scenario == "post-enable-foreign" && registered {
					unit["DropInPaths"] = dbus.MakeVariant([]string{"/run/systemd/system/foreign.conf"})
				}
				properties := unit
				if call.Body[0] == "org.freedesktop.systemd1.Service" {
					properties = service
				}
				body = []any{properties}
			case object == managerPath && iface == managerInterface && member == "Reload":
				if len(call.Body) != 0 {
					return errors.New("reload carried unexpected arguments")
				}
				p.reloads.Add(1)
				switch scenario {
				case "blocked-reload":
					close(p.entered)
					<-p.release
					return nil
				case "reload-error":
					if err := sendManagerReply(wire, call, "org.freedesktop.DBus.Error.Failed", "synthetic-sensitive-reload"); err != nil {
						return err
					}
					continue
				case "malformed-reload":
					body = []any{uint32(0)}
				case "replaced-unit":
					if err := os.WriteFile(filename, []byte("owned foreign replacement"), 0644); err != nil {
						return err
					}
				}
			case object == managerPath && iface == managerInterface && member == "EnableUnitFiles":
				p.enables.Add(1)
				if len(call.Body) != 3 || call.Body[1] != false || call.Body[2] != false {
					return errors.New("registration used runtime or forced enablement")
				}
				units, ok := call.Body[0].([]string)
				if !ok || !slices.Equal(units, []string{UnitName}) {
					return errors.New("registration enabled another unit")
				}
				if scenario != "missing-link" {
					target := UnitPath
					if scenario == "foreign-link" {
						target = "/owned-foreign"
					}
					if err := createLink(target); err != nil {
						return err
					}
				}
				registered = true
				if scenario == "enable-error" {
					if err := sendManagerReply(wire, call, "org.freedesktop.DBus.Error.Failed", "synthetic-sensitive-enable"); err != nil {
						return err
					}
					continue
				}
				changes := []fixtureUnitFileChange{{"symlink", "/etc/systemd/system/" + wantsDirectory + "/" + UnitName, UnitPath}}
				if scenario == "concurrent-winner" {
					changes = nil
				}
				switch scenario {
				case "foreign-change-path":
					changes[0].Path = "/etc/systemd/system/other.service"
				case "foreign-change-source":
					changes[0].Source = "/usr/lib/systemd/system/" + UnitName
				case "unlink-change":
					changes[0].Type = "unlink"
				case "additional-change":
					changes = append(changes, changes[0])
				}
				body = []any{scenario != "malformed-enable", changes}
				if scenario == "wrong-change-type" {
					body[1] = []string{"symlink", UnitPath}
				}
			default:
				return errors.New("registration emitted an unexpected or process-changing method")
			}
			if err := sendManagerReply(wire, call, "", body...); err != nil {
				return err
			}
		}
	})
	return p
}

func (p *registrationPeer) connect(ctx context.Context) (*systemdConnection, error) {
	return connectPrivateManager(ctx, p.peer.path, int32(os.Getpid()))
}

func TestLinuxRegistrationAdmitsOnlyOwnedPersistentState(t *testing.T) {
	for _, scenario := range []string{"fresh", "prepared", "pending-reload", "already-enabled", "concurrent-winner", "vendor", "orphan-loaded", "unowned-enablement", "reload-error", "malformed-reload", "replaced-unit", "missing-link", "foreign-link", "enable-error", "malformed-enable", "foreign-change-path", "foreign-change-source", "unlink-change", "additional-change", "wrong-change-type", "post-enable-disabled", "post-enable-foreign"} {
		t.Run(scenario, func(t *testing.T) {
			filename, spec, _ := unitFileFixture(t)
			p := newRegistrationPeer(t, filename, spec, scenario)
			s, err := openServiceAt(t.Context(), spec, filename, p.connect)
			if slices.Contains([]string{"vendor", "orphan-loaded", "unowned-enablement"}, scenario) {
				if s != nil {
					s.Close()
				}
				if !errors.Is(err, ErrUnit) || p.reloads.Load() != 0 || p.enables.Load() != 0 {
					t.Fatal("foreign registration preflight changed state", err)
				}
				return
			}
			if err != nil {
				t.Fatal("owned registration preflight failed", err)
			}
			defer s.Close()
			err = s.Register(t.Context())
			if slices.Contains([]string{"fresh", "prepared", "pending-reload", "already-enabled", "concurrent-winner"}, scenario) {
				if err != nil {
					t.Fatal("owned registration failed", err)
				}
				if status, err := s.Status(t.Context()); err != nil || status != Enabled {
					t.Fatal("successful registration lacked joined evidence", status, err)
				}
				reloads, enables := p.reloads.Load(), p.enables.Load()
				if (scenario == "already-enabled" && (reloads != 0 || enables != 0)) || (scenario != "already-enabled" && (reloads != 2 || enables != 1)) {
					t.Fatal("unexpected registration mutations", reloads, enables)
				}
				var stamp unix.Stat_t
				if unix.Lstat(filename, &stamp) != nil {
					t.Fatal("registered file unavailable")
				}
				if err := s.Register(t.Context()); err != nil || p.reloads.Load() != reloads || p.enables.Load() != enables {
					t.Fatal("retry repeated manager mutations", err)
				}
				s.Close()
				var after unix.Stat_t
				if unix.Lstat(filename, &after) != nil || !sameStamp(stamp, after) {
					t.Fatal("retry or close rewrote the unit")
				}
				if _, err := s.Status(t.Context()); !errors.Is(err, ErrUnit) {
					t.Fatal("closed controller observed state", err)
				}
				if err := s.Register(t.Context()); !errors.Is(err, ErrUnit) {
					t.Fatal("closed controller registered", err)
				}
			} else {
				if err == nil || strings.Contains(err.Error(), "synthetic-sensitive") {
					t.Fatal("incomplete registration accepted or peer error exposed", err)
				}
				if slices.Contains([]string{"reload-error", "malformed-reload", "replaced-unit"}, scenario) && p.enables.Load() != 0 {
					t.Fatal("registration enabled after rejected reload")
				}
				data, readErr := os.ReadFile(filename)
				if readErr != nil || (scenario != "replaced-unit" && !Matches(data, spec)) || (scenario == "replaced-unit" && string(data) != "owned foreign replacement") {
					t.Fatal("uncertain outcome did not retain the current unit", readErr)
				}
			}
		})
	}
}

func TestLinuxRegistrationSerializesAndJoinsCancellation(t *testing.T) {
	for _, scenario := range []string{"concurrent", "canceled", "blocked-reload"} {
		t.Run(scenario, func(t *testing.T) {
			filename, spec, _ := unitFileFixture(t)
			p := newRegistrationPeer(t, filename, spec, scenario)
			defer close(p.release)
			s, err := openServiceAt(t.Context(), spec, filename, p.connect)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if scenario == "concurrent" {
				var workers sync.WaitGroup
				for range 12 {
					workers.Go(func() {
						if err := s.Register(t.Context()); err != nil {
							t.Error(err)
						}
					})
				}
				workers.Wait()
				if p.enables.Load() != 1 || p.reloads.Load() != 2 {
					t.Fatal("concurrent registration repeated mutations")
				}
				return
			}
			if scenario == "canceled" {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if err := s.Register(ctx); !errors.Is(err, context.Canceled) {
					t.Fatal("canceled registration proceeded", err)
				}
				if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) || p.reloads.Load() != 0 || p.enables.Load() != 0 {
					t.Fatal("canceled registration changed native state", err)
				}
				return
			}
			done := make(chan error, 1)
			go func() { done <- s.Register(t.Context()) }()
			select {
			case <-p.entered:
			case <-time.After(time.Second):
				t.Fatal("registration did not enter the held manager call")
			}
			closed := make(chan struct{})
			go func() { s.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("controller close waited on its own operation lock")
			}
			if err := <-done; err == nil {
				t.Fatal("interrupted registration reported success")
			}
			data, err := os.ReadFile(filename)
			if err != nil || !Matches(data, spec) || p.enables.Load() != 0 {
				t.Fatal("cancellation removed published evidence or enabled the service", err)
			}
		})
	}
}
