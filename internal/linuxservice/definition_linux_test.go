package linuxservice

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestLinuxDefinitionResolvesBeforeAdmittingAbsence(t *testing.T) {
	for _, scenario := range []string{"absent", "matching", "lookup-error", "foreign-object", "malformed-object", "malformed-properties", "vendor", "alias", "retained-command", "changed-state", "changed-drop-in", "changed-load-state"} {
		t.Run(scenario, func(t *testing.T) {
			root := managerFixture(t)
			spec, loadedUnit, loadedService := stateFixture()
			unit, service := absentDefinitionFixture()
			if scenario == "matching" || scenario == "vendor" {
				unit, service = loadedUnit, loadedService
			}
			peer := newManagerPeer(t, root, func(wire *net.UnixConn) error {
				r, err := authenticateManagerPeer(wire, false)
				if err != nil {
					return err
				}
				call, err := dbus.DecodeMessage(r)
				if err != nil {
					return err
				}
				if call.Type != dbus.TypeMethodCall || call.Headers[dbus.FieldPath].Value() != managerPath || call.Headers[dbus.FieldInterface].Value() != managerInterface || call.Headers[dbus.FieldMember].Value() != "LoadUnit" || len(call.Body) != 1 || call.Body[0] != UnitName {
					return errors.New("definition lookup did not resolve the fixed service through LoadUnit")
				}
				switch scenario {
				case "lookup-error":
					return sendManagerReply(wire, call, "org.freedesktop.systemd1.NoSuchUnit", "synthetic-sensitive-definition")
				case "foreign-object":
					return sendManagerReply(wire, call, "", dbus.ObjectPath("/org/freedesktop/systemd1/unit/foreign_2eservice"))
				case "malformed-object":
					return sendManagerReply(wire, call, "", string(unitObjectPath))
				}
				if err := sendManagerReply(wire, call, "", unitObjectPath); err != nil {
					return err
				}
				for i, iface := range []string{"Unit", "Service", "Unit"} {
					call, err := dbus.DecodeMessage(r)
					if err != nil {
						return err
					}
					if call.Type != dbus.TypeMethodCall || call.Headers[dbus.FieldPath].Value() != unitObjectPath || call.Headers[dbus.FieldInterface].Value() != "org.freedesktop.DBus.Properties" || call.Headers[dbus.FieldMember].Value() != "GetAll" || len(call.Body) != 1 || call.Body[0] != "org.freedesktop.systemd1."+iface {
						return errors.New("definition resolution emitted an unexpected method or interface")
					}
					if scenario == "malformed-properties" {
						return sendManagerReply(wire, call, "", uint32(0))
					}
					properties := unit
					if iface == "Service" {
						properties = service
					}
					if i == 0 && scenario == "vendor" {
						unit["FragmentPath"] = dbus.MakeVariant("/usr/lib/systemd/system/" + UnitName)
					}
					if i == 0 && scenario == "alias" {
						unit["Names"] = dbus.MakeVariant([]string{UnitName, "foreign.service"})
					}
					if i == 1 && scenario == "retained-command" {
						service["ExecStopEx"] = dbus.MakeVariant([]execCommand{{Path: "/foreign", Args: []string{"/foreign"}}})
					}
					if i == 2 {
						switch scenario {
						case "changed-state":
							unit["StateChangeTimestampMonotonic"] = dbus.MakeVariant(uint64(1))
						case "changed-drop-in":
							unit["DropInPaths"] = dbus.MakeVariant([]string{"/run/systemd/system/foreign.conf"})
						case "changed-load-state":
							unit["LoadState"] = dbus.MakeVariant("loaded")
						}
					}
					if err := sendManagerReply(wire, call, "", properties); err != nil {
						return err
					}
					if i == 1 && (scenario == "vendor" || scenario == "alias" || scenario == "retained-command") {
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
			definition, err := c.loadDefinition(context.Background(), spec)
			switch scenario {
			case "absent":
				if err != nil || definition.Present || definition.State.Active != "inactive" || definition.State.PID != 0 {
					t.Fatal("resolved absence rejected", definition, err)
				}
			case "matching":
				if err != nil || !definition.Present || definition.State.PID != 42 {
					t.Fatal("resolved matching definition rejected", definition, err)
				}
			default:
				want := ErrUnit
				if scenario == "lookup-error" {
					want = ErrManager
				}
				if !errors.Is(err, want) || definition != (unitDefinition{}) || strings.Contains(err.Error(), "synthetic-sensitive") {
					t.Fatal("invalid resolution admitted or exposed peer data", definition, err)
				}
			}
		})
	}
}
