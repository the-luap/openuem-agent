package linuxservice

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestLinuxLoadedUnitObservationUsesTypedReadOnlyCalls(t *testing.T) {
	for _, scenario := range []string{"running", "missing", "foreign-object", "malformed-properties", "foreign-service", "changed-state", "changed-drop-in"} {
		t.Run(scenario, func(t *testing.T) {
			root := managerFixture(t)
			spec, unit, service := stateFixture()
			peer := newManagerPeer(t, root, func(wire *net.UnixConn) error {
				r, err := authenticateManagerPeer(wire, false)
				if err != nil {
					return err
				}
				call, err := dbus.DecodeMessage(r)
				if err != nil {
					return err
				}
				if call.Type != dbus.TypeMethodCall || call.Headers[dbus.FieldPath].Value() != managerPath || call.Headers[dbus.FieldInterface].Value() != managerInterface || call.Headers[dbus.FieldMember].Value() != "GetUnit" || len(call.Body) != 1 || call.Body[0] != UnitName {
					return errors.New("unit observation did not use the fixed read-only lookup")
				}
				if scenario == "missing" {
					return sendManagerReply(wire, call, "org.freedesktop.systemd1.NoSuchUnit", "synthetic-sensitive-missing-unit")
				}
				object := unitObjectPath
				if scenario == "foreign-object" {
					object = "/org/freedesktop/systemd1/unit/other_2eservice"
				}
				if err := sendManagerReply(wire, call, "", object); err != nil {
					return err
				}
				if scenario == "foreign-object" {
					return nil
				}
				for i, iface := range []string{"Unit", "Service", "Unit"} {
					call, err := dbus.DecodeMessage(r)
					if err != nil {
						return err
					}
					if call.Type != dbus.TypeMethodCall || call.Headers[dbus.FieldPath].Value() != unitObjectPath || call.Headers[dbus.FieldInterface].Value() != "org.freedesktop.DBus.Properties" || call.Headers[dbus.FieldMember].Value() != "GetAll" || len(call.Body) != 1 || call.Body[0] != "org.freedesktop.systemd1."+iface {
						return errors.New("unit observation emitted an unexpected method or interface")
					}
					if scenario == "malformed-properties" {
						return sendManagerReply(wire, call, "", uint32(0))
					}
					properties := unit
					if iface == "Service" {
						properties = service
					}
					if i == 1 && scenario == "foreign-service" {
						properties["User"] = dbus.MakeVariant("nobody")
					}
					if i == 2 && scenario == "changed-state" {
						properties["StateChangeTimestampMonotonic"] = dbus.MakeVariant(uint64(301))
					}
					if i == 2 && scenario == "changed-drop-in" {
						properties["DropInPaths"] = dbus.MakeVariant([]string{"/run/systemd/system/service.d/foreign.conf"})
					}
					if err := sendManagerReply(wire, call, "", properties); err != nil {
						return err
					}
					if i == 1 && scenario == "foreign-service" {
						return nil
					}
				}
				return nil
			})
			c, err := connectPrivateManager(context.Background(), peer.path, int32(os.Getpid()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			state, err := c.readLoadedState(context.Background(), spec)
			if scenario == "running" {
				if err != nil || state.PID != 42 || state.StartedMonotonic != 200 || state.Invocation[0] != 1 {
					t.Fatal("native codec lost the admitted runtime identity", state, err)
				}
			} else {
				want := ErrUnit
				if scenario == "missing" {
					want = errUnitNotLoaded
				}
				if !errors.Is(err, want) || state != (unitState{}) {
					t.Fatal("invalid loaded unit was accepted", state, err)
				}
			}
		})
	}
}
