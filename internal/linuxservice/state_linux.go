package linuxservice

import (
	"context"
	"fmt"

	"github.com/godbus/dbus/v5"
)

const unitObjectPath dbus.ObjectPath = "/org/freedesktop/systemd1/unit/openuem_2dagent_2eservice"

// readLoadedState performs only reads. It never loads, starts or replaces a
// unit as a side effect of observation. A missing loaded object is distinct
// from filesystem absence; the caller must inspect the protected unit file.
func (c *systemdConnection) readLoadedState(ctx context.Context, spec Spec) (unitState, error) {
	definition, err := c.observeDefinition(ctx, spec, false)
	return definition.State, err
}

// loadDefinition resolves the manager's complete unit search path before a
// caller may publish a new canonical file. Loading metadata starts no service.
func (c *systemdConnection) loadDefinition(ctx context.Context, spec Spec) (unitDefinition, error) {
	return c.observeDefinition(ctx, spec, true)
}

func (c *systemdConnection) observeDefinition(ctx context.Context, spec Spec, load bool) (unitDefinition, error) {
	if !spec.Valid() {
		return unitDefinition{}, ErrUnit
	}
	method := "GetUnit"
	if load {
		method = "LoadUnit"
	}
	body, err := c.call(ctx, managerPath, managerInterface+"."+method, UnitName)
	if err != nil {
		return unitDefinition{}, fmt.Errorf("systemd %s: %w", method, err)
	}
	if len(body) != 1 || body[0] != unitObjectPath {
		return unitDefinition{}, ErrUnit
	}
	get := func(iface string) (map[string]dbus.Variant, error) {
		body, err := c.call(ctx, unitObjectPath, "org.freedesktop.DBus.Properties.GetAll", "org.freedesktop.systemd1."+iface)
		if err != nil {
			return nil, fmt.Errorf("systemd %s properties: %w", iface, err)
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
		return unitDefinition{}, err
	}
	service, err := get("Service")
	if err != nil {
		return unitDefinition{}, err
	}
	decode := func(unit, service map[string]dbus.Variant) (unitDefinition, error) {
		if load && propertyEquals(unit, "LoadState", "not-found") {
			state, err := decodeAbsentDefinition(unit, service)
			return unitDefinition{State: state}, err
		}
		state, err := decodeUnitState(spec, unit, service)
		return unitDefinition{Present: true, State: state}, err
	}
	before, err := decode(unit, service)
	if err != nil {
		return unitDefinition{}, err
	}
	unit, err = get("Unit")
	if err != nil {
		return unitDefinition{}, err
	}
	after, err := decode(unit, service)
	if err != nil || before != after {
		return unitDefinition{}, ErrUnit
	}
	return after, nil
}
