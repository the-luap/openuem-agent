package linuxservice

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func liveSystemdFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENUEM_TEST_LIVE_SYSTEMD") != "owned-virtual-machine" {
		t.Skip("requires the owned virtual systemd machine")
	}
	marker, err := os.ReadFile("/etc/openuem-systemd-fixture")
	if err != nil || string(marker) != "owned-virtual-machine\n" {
		t.Fatal("missing owned guest marker")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !bytes.Contains(cmdline, []byte("openuem_fixture=owned-virtual-machine")) {
		t.Fatal("missing owned kernel marker")
	}
	manager, err := os.ReadFile("/proc/1/comm")
	if err != nil || string(manager) != "systemd\n" || os.Geteuid() != 0 {
		t.Fatal("fixture requires its own root PID-1 systemd manager")
	}
	var fs unix.Statfs_t
	if unix.Statfs("/", &fs) != nil || (fs.Type != unix.RAMFS_MAGIC && fs.Type != unix.TMPFS_MAGIC) {
		t.Fatal("guest root must be the owned in-memory filesystem")
	}
}

func TestLinuxLiveSystemdAbsentDefinition(t *testing.T) {
	liveSystemdFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := connectSystemd(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	spec := Spec{Executable: "/fixture/linuxservice.test", IdentityDirectory: "/fixture/identity"}
	definition, err := c.loadDefinition(ctx, spec)
	if err != nil {
		// Only selected properties from the owned absent unit are diagnostics.
		for _, iface := range []string{"Unit", "Service"} {
			body, readErr := c.call(ctx, unitObjectPath, "org.freedesktop.DBus.Properties.GetAll", "org.freedesktop.systemd1."+iface)
			if readErr != nil || len(body) != 1 {
				t.Log("owned definition unavailable", readErr)
				continue
			}
			values, ok := body[0].(map[string]dbus.Variant)
			if !ok {
				continue
			}
			for _, name := range []string{"LoadState", "UnitFileState", "Names", "DropInPaths", "InvocationID", "NeedDaemonReload", "ActiveState", "SubState", "Job", "MainPID", "ExecMainPID", "ExecMainStartTimestampMonotonic", "ExecStartEx"} {
				if value, ok := values[name]; ok {
					t.Logf("owned absent %s.%s: %v", iface, name, value)
				}
			}
		}
		t.Fatal("actual absent definition rejected", err)
	}
	if definition.Present || definition.State.Active != "inactive" || definition.State.PID != 0 {
		t.Fatal("unexpected owned absent definition", definition)
	}
}

func TestLinuxLiveSystemdPrivateManager(t *testing.T) {
	liveSystemdFixture(t)
	// Every connection exercises the auth-to-binary boundary with an immediate
	// first call; one successful warm connection cannot hide the former stall.
	for range 20 {
		checkLiveSystemdManager(t)
	}
}

func checkLiveSystemdManager(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := connectSystemd(ctx)
	if err != nil {
		t.Fatal("actual PID-1 private connection failed", err)
	}
	defer c.Close()
	body, err := c.call(ctx, managerPath, "org.freedesktop.DBus.Properties.GetAll", managerInterface)
	if err != nil || len(body) != 1 {
		t.Fatal("actual system manager properties unavailable", err)
	}
	properties, ok := body[0].(map[string]dbus.Variant)
	version, versionOK := property[string](properties, "Version")
	if !ok || !versionOK || version == "" {
		t.Fatal("actual system manager version unavailable")
	}
}

func TestLinuxLiveSystemdOwnedDefinition(t *testing.T) {
	liveSystemdFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := connectSystemd(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	spec := Spec{Executable: "/fixture/linuxservice.test", IdentityDirectory: "/fixture/identity"}
	if _, err := os.Lstat(UnitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("guest unit is not absent before publication", err)
	}
	u, err := openUnitFile(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	defer func() {
		if present, err := u.inspect(); err == nil && present {
			if err := os.Remove(UnitPath); err != nil {
				t.Error(err)
			}
			if _, err := c.call(ctx, managerPath, managerInterface+".Reload"); err != nil {
				t.Error("owned fixture reload failed", err)
			}
		}
	}()
	if err := u.publish(ctx); err != nil {
		t.Fatal("actual guest publication failed", err)
	}
	definition, err := c.loadDefinition(ctx, spec)
	if err != nil || !definition.Present || definition.State.Active != "inactive" || definition.State.Enabled || definition.State.PID != 0 {
		t.Fatal("actual never-started canonical definition rejected", definition, err)
	}
	if present, err := u.inspect(); err != nil || !present {
		t.Fatal("loading the definition changed its file", err)
	}
}

func TestLinuxLiveSystemdOwnedEnablement(t *testing.T) {
	liveSystemdFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := connectSystemd(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	spec := Spec{Executable: "/fixture/linuxservice.test", IdentityDirectory: "/fixture/identity"}
	definition, err := c.loadDefinition(ctx, spec)
	if err != nil || definition.Present {
		t.Fatal("fixture definition was not absent", definition, err)
	}
	u, err := openUnitFile(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	e, err := openUnitEnablement()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if enabled, err := e.inspect(); err != nil || enabled {
		t.Fatal("fixture link was not absent", enabled, err)
	}
	defer func() {
		if enabled, err := e.inspect(); err == nil && enabled {
			if err := os.Remove(filepath.Join("/etc/systemd/system", wantsDirectory, UnitName)); err != nil {
				t.Error(err)
			}
		}
		if present, err := u.inspect(); err == nil && present {
			if err := os.Remove(UnitPath); err != nil {
				t.Error(err)
			}
			if _, err := c.call(ctx, managerPath, managerInterface+".Reload"); err != nil {
				t.Error("owned fixture reload failed", err)
			}
		}
	}()
	if err := u.publish(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.call(ctx, managerPath, managerInterface+".Reload"); err != nil {
		t.Fatal(err)
	}
	definition, err = c.loadDefinition(ctx, spec)
	if err != nil || !definition.Present || definition.State.Enabled || definition.State.PID != 0 {
		t.Fatal("fixture unit was not canonically disabled", definition, err)
	}
	body, err := c.call(ctx, managerPath, managerInterface+".EnableUnitFiles", []string{UnitName}, false, false)
	if err != nil || len(body) != 2 || body[0] != true {
		t.Fatal("actual persistent enablement failed", err)
	}
	if enabled, err := e.inspect(); err != nil || !enabled {
		t.Fatal("actual manager-created link was not admitted", enabled, err)
	}
	if err := e.flush(ctx); err != nil {
		t.Fatal("actual manager-created link was not durably verified", err)
	}
	if _, err := c.call(ctx, managerPath, managerInterface+".Reload"); err != nil {
		t.Fatal(err)
	}
	definition, err = c.loadDefinition(ctx, spec)
	if err != nil || !definition.Present || !definition.State.Enabled || definition.State.Active != "inactive" || definition.State.PID != 0 {
		t.Fatal("actual enabled unit state was not admitted", definition, err)
	}
	if present, err := u.inspect(); err != nil || !present {
		t.Fatal("enablement changed the owned definition", err)
	}
}

func TestLinuxLiveSystemdServiceRegistration(t *testing.T) {
	liveSystemdFixture(t)
	for _, scenario := range []string{"fresh", "published-before-reload", "enabled-before-reload"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			spec := Spec{Executable: "/fixture/linuxservice.test", IdentityDirectory: "/fixture/identity"}
			defer cleanupLiveRegistration(t, spec)
			s, err := Open(ctx, spec)
			if err != nil {
				t.Fatal("actual service preflight failed", err)
			}
			defer s.Close()
			if status, err := s.Status(ctx); err != nil || status != NotRegistered {
				t.Fatal("fresh guest service was already registered", status, err)
			}
			if _, err := os.Lstat(UnitPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("preflight published a unit", err)
			}
			if scenario != "fresh" {
				if err := s.unit.publish(ctx); err != nil {
					t.Fatal(err)
				}
				if scenario == "enabled-before-reload" {
					if err := s.reload(ctx); err != nil {
						t.Fatal(err)
					}
					if _, err := s.connection.call(ctx, managerPath, managerInterface+".EnableUnitFiles", []string{UnitName}, false, false); err != nil {
						t.Fatal(err)
					}
				}
				s.Close()
				s, err = Open(ctx, spec)
				if err != nil {
					t.Fatal("interrupted registration could not be reopened", err)
				}
				defer s.Close()
			}
			if err := s.Register(ctx); err != nil {
				t.Fatal("actual service registration failed", err)
			}
			var before unix.Stat_t
			if unix.Lstat(UnitPath, &before) != nil {
				t.Fatal("registered unit unavailable")
			}
			if err := s.Register(ctx); err != nil {
				t.Fatal("retained registration retry failed", err)
			}
			if status, err := s.Status(ctx); err != nil || status != Enabled {
				t.Fatal("registration status was not enabled", status, err)
			}
			// systemd may collect an enabled but inactive unit between calls.
			// Resolve it again; a GetUnit cache miss says nothing about activity.
			definition, err := s.connection.loadDefinition(ctx, spec)
			state := definition.State
			if err != nil || !definition.Present || state.Active != "inactive" || state.PID != 0 || state.StartedMonotonic != 0 || state.Invocation != [16]byte{} {
				t.Fatal("registered service did not retain never-started state", state, err)
			}
			s.Close()
			var after unix.Stat_t
			if unix.Lstat(UnitPath, &after) != nil || !sameStamp(before, after) {
				t.Fatal("retry or close modified the installed definition")
			}
		})
	}
}

func cleanupLiveRegistration(t *testing.T, spec Spec) {
	t.Helper()
	// No service is started by these tests. Remove only files admitted again
	// under the exact owned guest contract, even if its previous owner closed.
	e, err := openUnitEnablement()
	if err != nil {
		t.Error("cannot admit fixture enablement cleanup", err)
		return
	}
	defer e.Close()
	if enabled, err := e.inspect(); err == nil && enabled {
		if err := os.Remove(filepath.Join("/etc/systemd/system", wantsDirectory, UnitName)); err != nil {
			t.Error(err)
		}
	}
	u, err := openUnitFile(spec)
	if err != nil {
		t.Error("cannot admit fixture definition cleanup", err)
		return
	}
	defer u.Close()
	if present, err := u.inspect(); err == nil && present {
		if err := os.Remove(UnitPath); err != nil {
			t.Error(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := connectSystemd(ctx)
	if err != nil {
		t.Error(err)
		return
	}
	defer c.Close()
	if _, err := c.call(ctx, managerPath, managerInterface+".Reload"); err != nil {
		t.Error("owned registration cleanup reload failed", err)
	}
}

func TestLinuxLiveSystemdForeignDefinition(t *testing.T) {
	liveSystemdFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := connectSystemd(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := os.Lstat(UnitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canonical guest unit already exists", err)
	}
	vendor := "/usr/lib/systemd/system/" + UnitName
	if err := os.MkdirAll(filepath.Dir(vendor), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(vendor); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("vendor fixture already exists", err)
	}
	data := []byte("[Unit]\nDescription=Owned foreign definition fixture\n[Service]\nType=oneshot\nExecStart=/bin/busybox true\n")
	if err := os.WriteFile(vendor, data, 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(vendor)
	spec := Spec{Executable: "/fixture/linuxservice.test", IdentityDirectory: "/fixture/identity"}
	if s, err := Open(ctx, spec); !errors.Is(err, ErrUnit) {
		if s != nil {
			s.Close()
		}
		t.Fatal("controller admitted an existing vendor service", err)
	}
	if _, err := c.loadDefinition(ctx, spec); !errors.Is(err, ErrUnit) {
		t.Fatal("resolved vendor service was not rejected", err)
	}
	body, err := c.call(ctx, unitObjectPath, "org.freedesktop.DBus.Properties.GetAll", "org.freedesktop.systemd1.Unit")
	if err != nil || len(body) != 1 {
		t.Fatal("actual vendor definition unavailable", err)
	}
	properties, ok := body[0].(map[string]dbus.Variant)
	if !ok || !propertyEquals(properties, "FragmentPath", vendor) {
		t.Fatal("fixture did not resolve the actual vendor definition")
	}
	if _, err := os.Lstat(UnitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("foreign definition acquired a canonical override", err)
	}
	retained, err := os.ReadFile(vendor)
	if err != nil || !bytes.Equal(retained, data) {
		t.Fatal("foreign definition was modified", err)
	}
}
