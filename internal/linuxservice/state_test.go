package linuxservice

import (
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

func stateFixture() (Spec, map[string]dbus.Variant, map[string]dbus.Variant) {
	spec := Spec{Executable: "/opt/OpenUEM agent/agent%u", IdentityDirectory: `/var/lib/OpenUEM $HOME/${USER}/"quoted"\identity%h`}
	variants := func(values map[string]any) map[string]dbus.Variant {
		result := make(map[string]dbus.Variant, len(values))
		for name, value := range values {
			result[name] = dbus.MakeVariant(value)
		}
		return result
	}
	unit := variants(map[string]any{
		"Id": UnitName, "Names": []string{UnitName}, "LoadState": "loaded", "FragmentPath": UnitPath, "SourcePath": "", "DropInPaths": []string{},
		"Transient": false, "NeedDaemonReload": false, "UnitFileState": "enabled", "ActiveState": "active", "SubState": "running",
		"StateChangeTimestampMonotonic": uint64(300), "InvocationID": []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, "Job": unitJob{Path: "/"},
	})
	service := variants(map[string]any{
		"Type": "exec", "User": "root", "Group": "root", "Restart": "on-failure", "KillMode": "mixed", "PIDFile": "", "BusName": "", "RootDirectory": "", "RootImage": "", "PAMName": "",
		"DynamicUser": false, "RemainAfterExit": false, "UMask": uint32(0077), "RestartUSec": uint64(5_000_000), "TimeoutStopUSec": uint64(120_000_000),
		"Environment": []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, "PassEnvironment": []string{}, "UnsetEnvironment": []string{}, "EnvironmentFiles": []environmentFile{},
		"MainPID": uint32(42), "ExecMainPID": uint32(42), "ExecMainStartTimestampMonotonic": uint64(200),
		"ExecStartEx": []execCommand{{Path: spec.Executable, Args: []string{spec.Executable, "serve", "-identity-directory", spec.IdentityDirectory}, Flags: []string{"no-env-expand"}, StartRealtime: 1000, StartMonotonic: 200, PID: 42}},
	})
	for _, name := range []string{"ExecConditionEx", "ExecStartPreEx", "ExecStartPostEx", "ExecReloadEx", "ExecStopEx", "ExecStopPostEx"} {
		service[name] = dbus.MakeVariant([]execCommand{})
	}
	return spec, unit, service
}

func TestLoadedUnitStateBindsLiteralInvocationAndRuntime(t *testing.T) {
	spec, unit, service := stateFixture()
	state, err := decodeUnitState(spec, unit, service)
	if err != nil || !state.Enabled || state.Active != "active" || state.Substate != "running" || state.PID != 42 || state.StartedMonotonic != 200 || state.ChangedMonotonic != 300 || state.Invocation[0] != 1 || state.JobID != 0 {
		t.Fatal("matching loaded state rejected", state, err)
	}
	for _, mode := range []string{"inactive", "failed", "activating", "deactivating"} {
		t.Run(mode, func(t *testing.T) {
			spec, unit, service := stateFixture()
			unit["UnitFileState"] = dbus.MakeVariant("disabled")
			unit["ActiveState"] = dbus.MakeVariant(mode)
			unit["SubState"] = dbus.MakeVariant(map[string]string{"inactive": "dead", "failed": "failed", "activating": "auto-restart", "deactivating": "stop-sigterm"}[mode])
			if mode != "deactivating" {
				service["MainPID"] = dbus.MakeVariant(uint32(0))
			}
			if mode == "activating" {
				unit["Job"] = dbus.MakeVariant(unitJob{ID: 17, Path: "/org/freedesktop/systemd1/job/17"})
			}
			state, err := decodeUnitState(spec, unit, service)
			if err != nil || state.Enabled || state.Active != mode {
				t.Fatal("valid transitional observation rejected", state, err)
			}
		})
	}
}

func TestLoadedUnitStateRequiresEveryTypedProperty(t *testing.T) {
	_, unit, service := stateFixture()
	for group, values := range map[string]map[string]dbus.Variant{"unit": unit, "service": service} {
		for name := range values {
			for _, mode := range []string{"missing", "wrong-type"} {
				t.Run(group+"/"+name+"/"+mode, func(t *testing.T) {
					spec, unit, service := stateFixture()
					values := unit
					if group == "service" {
						values = service
					}
					if mode == "missing" {
						delete(values, name)
					} else {
						values[name] = dbus.MakeVariant(uint16(0))
					}
					if _, err := decodeUnitState(spec, unit, service); !errors.Is(err, ErrUnit) {
						t.Fatal("missing or differently typed property was defaulted", err)
					}
				})
			}
		}
	}
}

func TestLoadedUnitStateRejectsForeignEffectiveConfiguration(t *testing.T) {
	cases := []struct {
		name, group, property string
		value                 any
	}{
		{"alias", "unit", "Names", []string{UnitName, "other.service"}},
		{"drop-in", "unit", "DropInPaths", []string{"/run/systemd/system/service.d/override.conf"}},
		{"foreign-fragment", "unit", "FragmentPath", "/run/systemd/system/" + UnitName},
		{"generated-source", "unit", "SourcePath", "/etc/init.d/openuem-agent"},
		{"stale-cache", "unit", "NeedDaemonReload", true},
		{"transient", "unit", "Transient", true},
		{"masked", "unit", "UnitFileState", "masked"},
		{"runtime-enabled", "unit", "UnitFileState", "enabled-runtime"},
		{"unloaded", "unit", "LoadState", "not-found"},
		{"active-exited", "unit", "SubState", "exited"},
		{"reloading", "unit", "ActiveState", "reloading"},
		{"empty-invocation", "unit", "InvocationID", make([]byte, 16)},
		{"short-invocation", "unit", "InvocationID", []byte{1}},
		{"foreign-job", "unit", "Job", unitJob{ID: 17, Path: "/org/freedesktop/systemd1/job/18"}},
		{"invalid-empty-job", "unit", "Job", unitJob{Path: "/other"}},
		{"forking", "service", "Type", "forking"},
		{"foreign-user", "service", "User", "nobody"},
		{"foreign-group", "service", "Group", "nogroup"},
		{"dynamic-user", "service", "DynamicUser", true},
		{"persistent-after-exit", "service", "RemainAfterExit", true},
		{"foreign-root", "service", "RootDirectory", "/other"},
		{"foreign-image", "service", "RootImage", "/other.raw"},
		{"pam", "service", "PAMName", "login"},
		{"pidfile", "service", "PIDFile", "/run/other.pid"},
		{"busname", "service", "BusName", "org.unapproved.Service"},
		{"restart", "service", "Restart", "always"},
		{"restart-delay", "service", "RestartUSec", uint64(0)},
		{"stop-timeout", "service", "TimeoutStopUSec", uint64(100)},
		{"kill-mode", "service", "KillMode", "process"},
		{"umask", "service", "UMask", uint32(0022)},
		{"environment", "service", "Environment", []string{serviceEnvironment, "LD_PRELOAD=/unapproved.so"}},
		{"pass-environment", "service", "PassEnvironment", []string{"LD_PRELOAD"}},
		{"unset-environment", "service", "UnsetEnvironment", []string{"PATH"}},
		{"environment-file", "service", "EnvironmentFiles", []environmentFile{{Path: "/other.env"}}},
		{"missing-pid", "service", "MainPID", uint32(0)},
		{"manager-pid", "service", "MainPID", uint32(1)},
		{"overflow-pid", "service", "MainPID", uint32(1 << 31)},
		{"other-pid", "service", "ExecMainPID", uint32(43)},
		{"missing-start", "service", "ExecMainStartTimestampMonotonic", uint64(0)},
		{"different-start", "service", "ExecMainStartTimestampMonotonic", uint64(201)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, unit, service := stateFixture()
			values := unit
			if tc.group == "service" {
				values = service
			}
			values[tc.property] = dbus.MakeVariant(tc.value)
			if _, err := decodeUnitState(spec, unit, service); !errors.Is(err, ErrUnit) {
				t.Fatal("foreign effective state admitted", err)
			}
		})
	}
	for _, scenario := range []string{"other-executable", "other-argv", "extra-argv", "environment-expansion", "ignore-failure", "privileged", "second-command", "empty-command", "other-pid", "other-start", "exited"} {
		t.Run(scenario, func(t *testing.T) {
			spec, unit, service := stateFixture()
			commands, _ := property[[]execCommand](service, "ExecStartEx")
			switch scenario {
			case "other-executable":
				commands[0].Path = "/other/agent"
			case "other-argv":
				commands[0].Args[3] = "/other/identity"
			case "extra-argv":
				commands[0].Args = append(commands[0].Args, "--other")
			case "environment-expansion":
				commands[0].Flags = nil
			case "ignore-failure":
				commands[0].Flags = append(commands[0].Flags, "ignore-failure")
			case "privileged":
				commands[0].Flags = append(commands[0].Flags, "privileged")
			case "second-command":
				commands = append(commands, commands[0])
			case "empty-command":
				commands = nil
			case "other-pid":
				commands[0].PID++
			case "other-start":
				commands[0].StartMonotonic++
			case "exited":
				commands[0].ExitMonotonic = 400
			}
			service["ExecStartEx"] = dbus.MakeVariant(commands)
			if _, err := decodeUnitState(spec, unit, service); !errors.Is(err, ErrUnit) {
				t.Fatal("foreign command admitted", err)
			}
		})
	}
	for _, hook := range []string{"ExecConditionEx", "ExecStartPreEx", "ExecStartPostEx", "ExecReloadEx", "ExecStopEx", "ExecStopPostEx"} {
		t.Run(hook, func(t *testing.T) {
			spec, unit, service := stateFixture()
			service[hook] = service["ExecStartEx"]
			if _, err := decodeUnitState(spec, unit, service); !errors.Is(err, ErrUnit) {
				t.Fatal("additional executable hook admitted", err)
			}
		})
	}
}
