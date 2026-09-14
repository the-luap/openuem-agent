package linuxservice

import "github.com/godbus/dbus/v5"

type unitDefinition struct {
	Present bool
	State   unitState
}

// An unloaded lookup is not evidence of absence. Only the manager's resolved
// not-found definition, with no code, source, job or process, admits a new file.
func decodeAbsentDefinition(unit, service map[string]dbus.Variant) (unitState, error) {
	fail := func() (unitState, error) { return unitState{}, ErrUnit }
	if len(unit) > 1024 || len(service) > 1024 {
		return fail()
	}
	for name, want := range map[string]string{"Id": UnitName, "LoadState": "not-found", "FragmentPath": "", "SourcePath": "", "UnitFileState": "", "ActiveState": "inactive", "SubState": "dead"} {
		if !propertyEquals(unit, name, want) {
			return fail()
		}
	}
	if !propertyStrings(unit, "Names", UnitName) || !propertyStrings(unit, "DropInPaths") || !propertyEquals(unit, "Transient", false) || !propertyEquals(unit, "NeedDaemonReload", false) || !propertyEquals(unit, "Job", unitJob{Path: "/"}) {
		return fail()
	}
	if !propertyEquals(service, "MainPID", uint32(0)) || !propertyEquals(service, "ExecMainPID", uint32(0)) || !propertyEquals(service, "ExecMainStartTimestampMonotonic", uint64(0)) {
		return fail()
	}
	for _, name := range []string{"ExecConditionEx", "ExecStartPreEx", "ExecStartEx", "ExecStartPostEx", "ExecReloadEx", "ExecStopEx", "ExecStopPostEx"} {
		commands, ok := property[[]execCommand](service, name)
		if !ok || len(commands) != 0 {
			return fail()
		}
	}
	state := unitState{Active: "inactive", Substate: "dead"}
	invocation, ok := property[[]byte](unit, "InvocationID")
	if !ok || len(invocation) != 0 {
		return fail()
	}
	if state.ChangedMonotonic, ok = property[uint64](unit, "StateChangeTimestampMonotonic"); !ok {
		return fail()
	}
	return state, nil
}
