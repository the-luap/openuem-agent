package linuxservice

import (
	"context"
	"fmt"
	"maps"

	"github.com/godbus/dbus/v5"
)

const unitObjectPath dbus.ObjectPath = "/org/freedesktop/systemd1/unit/openuem_2dagent_2eservice"

// Admitted configuration and typed runtime metadata straddle a transition.
// No caller may treat this as an admitted process observation.
var errUnitTransition = fmt.Errorf("%w: runtime state changed during observation", ErrUnit)

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
	beforeUnit := unit
	before, beforeErr := decode(beforeUnit, service)
	afterUnit, err := get("Unit")
	if err != nil {
		if beforeErr != nil {
			return unitDefinition{}, beforeErr
		}
		return unitDefinition{}, err
	}
	after, afterErr := decode(afterUnit, service)
	if beforeErr != nil || afterErr != nil {
		if (beforeErr == nil && crossedUnitTransition(spec, before, beforeUnit, afterUnit, service)) ||
			(afterErr == nil && crossedUnitTransition(spec, after, afterUnit, beforeUnit, service)) {
			return unitDefinition{}, errUnitTransition
		}
		return unitDefinition{}, ErrUnit
	}
	if before != after {
		return unitDefinition{}, errUnitTransition
	}
	return after, nil
}

// A service sample can fall on either side of a unit transition. Require one
// fully admitted sample, valid runtime metadata on the other side and identical
// admitted configuration after substituting only runtime fields. Return no
// admitted observation; the start controller must read all properties again.
func crossedUnitTransition(spec Spec, stable unitDefinition, stableUnit, movingUnit, service map[string]dbus.Variant) bool {
	if !stable.Present {
		return false
	}
	if _, err := decodeUnitRuntime(movingUnit); err != nil {
		return false
	}
	joined := maps.Clone(movingUnit)
	for _, name := range []string{"ActiveState", "SubState", "StateChangeTimestampMonotonic", "InvocationID", "Job"} {
		joined[name] = stableUnit[name]
	}
	state, err := decodeUnitState(spec, joined, service)
	return err == nil && state == stable.State
}
