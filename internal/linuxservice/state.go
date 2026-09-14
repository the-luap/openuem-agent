package linuxservice

import (
	"reflect"
	"slices"
	"strconv"

	"github.com/godbus/dbus/v5"
)

const serviceEnvironment = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// unitState is an observation of an already loaded, matching definition. A
// running main process is not proof that the enrolled agent is ready.
type unitState struct {
	Enabled                            bool
	Active, Substate                   string
	PID                                uint32
	StartedMonotonic, ChangedMonotonic uint64
	Invocation                         [16]byte
	JobID                              uint32
}

type execCommand struct {
	Path                                                       string
	Args, Flags                                                []string
	StartRealtime, StartMonotonic, ExitRealtime, ExitMonotonic uint64
	PID                                                        uint32
	Code, Status                                               int32
}

type environmentFile struct {
	Path          string
	IgnoreMissing bool
}
type unitJob struct {
	ID   uint32
	Path dbus.ObjectPath
}

// Properties must carry their actual D-Bus type. Missing values and permissive
// numeric/string conversions cannot silently become a desired zero/default.
func property[T any](values map[string]dbus.Variant, name string) (T, bool) {
	var result T
	v, ok := values[name]
	if !ok || v.Signature() != dbus.SignatureOfType(reflect.TypeFor[T]()) || v.Store(&result) != nil {
		return result, false
	}
	return result, true
}

func propertyEquals[T comparable](values map[string]dbus.Variant, name string, expected T) bool {
	actual, ok := property[T](values, name)
	return ok && actual == expected
}

func propertyStrings(values map[string]dbus.Variant, name string, expected ...string) bool {
	actual, ok := property[[]string](values, name)
	return ok && slices.Equal(actual, expected)
}

func decodeUnitState(spec Spec, unit, service map[string]dbus.Variant) (unitState, error) {
	fail := func() (unitState, error) { return unitState{}, ErrUnit }
	if !spec.Valid() || len(unit) > 1024 || len(service) > 1024 {
		return fail()
	}
	for name, expected := range map[string]string{"Id": UnitName, "LoadState": "loaded", "FragmentPath": UnitPath, "SourcePath": ""} {
		if !propertyEquals(unit, name, expected) {
			return fail()
		}
	}
	if !propertyStrings(unit, "Names", UnitName) || !propertyStrings(unit, "DropInPaths") || !propertyEquals(unit, "Transient", false) || !propertyEquals(unit, "NeedDaemonReload", false) {
		return fail()
	}
	for name, expected := range map[string]string{"Type": "exec", "User": "root", "Group": "root", "Restart": "on-failure", "KillMode": "mixed", "PIDFile": "", "BusName": "", "RootDirectory": "", "RootImage": "", "PAMName": ""} {
		if !propertyEquals(service, name, expected) {
			return fail()
		}
	}
	if !propertyEquals(service, "DynamicUser", false) || !propertyEquals(service, "RemainAfterExit", false) || !propertyEquals(service, "UMask", uint32(0077)) || !propertyEquals(service, "RestartUSec", uint64(5_000_000)) || !propertyEquals(service, "TimeoutStopUSec", uint64(120_000_000)) || !propertyStrings(service, "Environment", serviceEnvironment) || !propertyStrings(service, "PassEnvironment") || !propertyStrings(service, "UnsetEnvironment") {
		return fail()
	}
	environmentFiles, ok := property[[]environmentFile](service, "EnvironmentFiles")
	if !ok || len(environmentFiles) != 0 {
		return fail()
	}
	for _, name := range []string{"ExecConditionEx", "ExecStartPreEx", "ExecStartPostEx", "ExecReloadEx", "ExecStopEx", "ExecStopPostEx"} {
		commands, ok := property[[]execCommand](service, name)
		if !ok || len(commands) != 0 {
			return fail()
		}
	}
	commands, ok := property[[]execCommand](service, "ExecStartEx")
	if !ok || len(commands) != 1 {
		return fail()
	}
	command := commands[0]
	if command.Path != spec.Executable || !slices.Equal(command.Args, []string{spec.Executable, "serve", "-identity-directory", spec.IdentityDirectory}) || !slices.Equal(command.Flags, []string{"no-env-expand"}) {
		return fail()
	}
	state := unitState{}
	enablement, ok := property[string](unit, "UnitFileState")
	if !ok || (enablement != "enabled" && enablement != "disabled") {
		return fail()
	}
	state.Enabled = enablement == "enabled"
	if state.Active, ok = property[string](unit, "ActiveState"); !ok {
		return fail()
	}
	if state.Substate, ok = property[string](unit, "SubState"); !ok {
		return fail()
	}
	if state.ChangedMonotonic, ok = property[uint64](unit, "StateChangeTimestampMonotonic"); !ok {
		return fail()
	}
	invocation, ok := property[[]byte](unit, "InvocationID")
	if !ok || len(invocation) != len(state.Invocation) {
		return fail()
	}
	copy(state.Invocation[:], invocation)
	job, ok := property[unitJob](unit, "Job")
	if !ok || (job.ID == 0 && job.Path != "/") || (job.ID != 0 && job.Path != dbus.ObjectPath("/org/freedesktop/systemd1/job/"+strconv.FormatUint(uint64(job.ID), 10))) {
		return fail()
	}
	state.JobID = job.ID
	if state.PID, ok = property[uint32](service, "MainPID"); !ok || state.PID == 1 || state.PID > 1<<31-1 {
		return fail()
	}
	if state.StartedMonotonic, ok = property[uint64](service, "ExecMainStartTimestampMonotonic"); !ok {
		return fail()
	}
	executedPID, ok := property[uint32](service, "ExecMainPID")
	if !ok {
		return fail()
	}
	switch state.Active {
	case "active":
		if state.Substate != "running" || state.PID == 0 || state.PID != executedPID || command.PID != state.PID || state.StartedMonotonic == 0 || command.StartMonotonic != state.StartedMonotonic || command.ExitMonotonic != 0 || state.Invocation == [16]byte{} {
			return fail()
		}
	case "inactive":
		if state.Substate != "dead" || state.PID != 0 {
			return fail()
		}
	case "failed":
		if state.Substate != "failed" || state.PID != 0 {
			return fail()
		}
	case "activating":
		if state.Substate != "start" && state.Substate != "start-post" && state.Substate != "auto-restart" {
			return fail()
		}
	case "deactivating":
		if !slices.Contains([]string{"stop", "stop-sigterm", "stop-sigkill", "stop-post", "final-sigterm", "final-sigkill"}, state.Substate) {
			return fail()
		}
	default:
		return fail()
	}
	return state, nil
}
