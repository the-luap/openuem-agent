package linuxservice

import (
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

func absentDefinitionFixture() (map[string]dbus.Variant, map[string]dbus.Variant) {
	unit := make(map[string]dbus.Variant)
	service := make(map[string]dbus.Variant)
	for name, value := range map[string]any{
		"Id": UnitName, "Names": []string{UnitName}, "LoadState": "not-found", "FragmentPath": "", "SourcePath": "", "UnitFileState": "", "ActiveState": "inactive", "SubState": "dead",
		"DropInPaths": []string{}, "Transient": false, "NeedDaemonReload": false, "Job": unitJob{Path: "/"}, "InvocationID": []byte{}, "StateChangeTimestampMonotonic": uint64(0),
	} {
		unit[name] = dbus.MakeVariant(value)
	}
	for name, value := range map[string]any{"MainPID": uint32(0), "ExecMainPID": uint32(0), "ExecMainStartTimestampMonotonic": uint64(0)} {
		service[name] = dbus.MakeVariant(value)
	}
	for _, name := range []string{"ExecConditionEx", "ExecStartPreEx", "ExecStartEx", "ExecStartPostEx", "ExecReloadEx", "ExecStopEx", "ExecStopPostEx"} {
		service[name] = dbus.MakeVariant([]execCommand{})
	}
	return unit, service
}

func TestAbsentDefinitionRequiresResolvedTypedAbsence(t *testing.T) {
	unit, service := absentDefinitionFixture()
	state, err := decodeAbsentDefinition(unit, service)
	if err != nil || state.Active != "inactive" || state.PID != 0 {
		t.Fatal("resolved absence rejected", state, err)
	}
	for group, values := range map[string]map[string]dbus.Variant{"unit": unit, "service": service} {
		for name := range values {
			for _, mode := range []string{"missing", "type"} {
				t.Run(group+"/"+name+"/"+mode, func(t *testing.T) {
					unit, service := absentDefinitionFixture()
					values := unit
					if group == "service" {
						values = service
					}
					if mode == "missing" {
						delete(values, name)
					} else {
						values[name] = dbus.MakeVariant(uint16(0))
					}
					if _, err := decodeAbsentDefinition(unit, service); !errors.Is(err, ErrUnit) {
						t.Fatal("incomplete negative evidence accepted", err)
					}
				})
			}
		}
	}
}

func TestAbsentDefinitionRejectsRetainedCodeAndActivity(t *testing.T) {
	for _, tc := range []struct {
		name, group, key string
		value            any
	}{
		{"loaded", "unit", "LoadState", "loaded"},
		{"masked", "unit", "LoadState", "masked"},
		{"load-error", "unit", "LoadState", "error"},
		{"foreign-source", "unit", "SourcePath", "/etc/init.d/foreign"},
		{"vendor-fragment", "unit", "FragmentPath", "/usr/lib/systemd/system/" + UnitName},
		{"drop-in", "unit", "DropInPaths", []string{"/etc/systemd/system/service.d/foreign.conf"}},
		{"alias", "unit", "Names", []string{UnitName, "other.service"}},
		{"enabled", "unit", "UnitFileState", "enabled"},
		{"dangling", "unit", "UnitFileState", "bad"},
		{"active", "unit", "ActiveState", "active"},
		{"running", "unit", "SubState", "running"},
		{"transient", "unit", "Transient", true},
		{"dirty", "unit", "NeedDaemonReload", true},
		{"pending-job", "unit", "Job", unitJob{ID: 1, Path: "/org/freedesktop/systemd1/job/1"}},
		{"invocation", "unit", "InvocationID", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
		{"live-pid", "service", "MainPID", uint32(42)},
		{"retained-pid", "service", "ExecMainPID", uint32(42)},
		{"retained-start", "service", "ExecMainStartTimestampMonotonic", uint64(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unit, service := absentDefinitionFixture()
			values := unit
			if tc.group == "service" {
				values = service
			}
			values[tc.key] = dbus.MakeVariant(tc.value)
			if _, err := decodeAbsentDefinition(unit, service); !errors.Is(err, ErrUnit) {
				t.Fatal("foreign or active definition accepted as absence", err)
			}
		})
	}
	for _, name := range []string{"ExecConditionEx", "ExecStartPreEx", "ExecStartEx", "ExecStartPostEx", "ExecReloadEx", "ExecStopEx", "ExecStopPostEx"} {
		t.Run(name, func(t *testing.T) {
			unit, service := absentDefinitionFixture()
			service[name] = dbus.MakeVariant([]execCommand{{Path: "/foreign", Args: []string{"/foreign"}}})
			if _, err := decodeAbsentDefinition(unit, service); !errors.Is(err, ErrUnit) {
				t.Fatal("retained executable was ignored", err)
			}
		})
	}
}

func TestLoadedDefinitionAllowsEmptyInvocationOnlyBeforeRunning(t *testing.T) {
	spec, unit, service := stateFixture()
	unit["InvocationID"] = dbus.MakeVariant([]byte{})
	if _, err := decodeUnitState(spec, unit, service); !errors.Is(err, ErrUnit) {
		t.Fatal("running process without invocation accepted", err)
	}
	unit["ActiveState"] = dbus.MakeVariant("inactive")
	unit["SubState"] = dbus.MakeVariant("dead")
	service["MainPID"] = dbus.MakeVariant(uint32(0))
	service["ExecMainPID"] = dbus.MakeVariant(uint32(0))
	service["ExecMainStartTimestampMonotonic"] = dbus.MakeVariant(uint64(0))
	commands, _ := property[[]execCommand](service, "ExecStartEx")
	commands[0].PID, commands[0].StartRealtime, commands[0].StartMonotonic = 0, 0, 0
	service["ExecStartEx"] = dbus.MakeVariant(commands)
	if _, err := decodeUnitState(spec, unit, service); err != nil {
		t.Fatal("never-started matching unit rejected", err)
	}
}
