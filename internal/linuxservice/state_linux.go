package linuxservice

import (
	"context"

	"github.com/godbus/dbus/v5"
)

const unitObjectPath dbus.ObjectPath = "/org/freedesktop/systemd1/unit/openuem_2dagent_2eservice"

// readLoadedState performs only reads. It never loads, starts or replaces a
// unit as a side effect of observation. A missing loaded object is distinct
// from filesystem absence; the caller must inspect the protected unit file.
func (c *systemdConnection) readLoadedState(ctx context.Context, spec Spec) (unitState, error) {
	if !spec.Valid() {
		return unitState{}, ErrUnit
	}
	body, err := c.call(ctx, managerPath, managerInterface+".GetUnit", UnitName)
	if err != nil {
		return unitState{}, err
	}
	if len(body) != 1 || body[0] != unitObjectPath {
		return unitState{}, ErrUnit
	}
	get := func(iface string) (map[string]dbus.Variant, error) {
		body, err := c.call(ctx, unitObjectPath, "org.freedesktop.DBus.Properties.GetAll", "org.freedesktop.systemd1."+iface)
		if err != nil {
			return nil, err
		}
		if len(body) != 1 {
			return nil, ErrUnit
		}
		properties, ok := body[0].(map[string]dbus.Variant)
		if !ok || len(properties) > 1024 {
			return nil, ErrUnit
		}
		return properties, nil
	}
	unit, err := get("Unit")
	if err != nil {
		return unitState{}, err
	}
	service, err := get("Service")
	if err != nil {
		return unitState{}, err
	}
	before, err := decodeUnitState(spec, unit, service)
	if err != nil {
		return unitState{}, err
	}
	unit, err = get("Unit")
	if err != nil {
		return unitState{}, err
	}
	after, err := decodeUnitState(spec, unit, service)
	if err != nil || before != after {
		return unitState{}, ErrUnit
	}
	return after, nil
}
