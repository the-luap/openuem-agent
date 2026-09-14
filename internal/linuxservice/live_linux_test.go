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
