package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/machardware"
	"io"
	"time"
)

var errHardwareReport = errors.New("individual Mac hardware report was not accepted")

func (a *Agent) setHardwareCapability(version int) {
	if a.individual == nil {
		return
	}
	accepted := int32(0)
	if a.individual.identity.Platform == "macos" && version == enrollment.HardwareInventoryVersion {
		accepted = int32(version)
	}
	a.individual.hardwareVersion.Store(accepted)
}

func (a *Agent) sendHardware(h *enrollment.HardwareInventory) error {
	return a.sendHardwareUsing(h, machardware.ReadBinding)
}

func (a *Agent) sendHardwareUsing(h *enrollment.HardwareInventory, readBinding func() (*enrollment.MacBindingProof, error)) error {
	if a.individual == nil || a.individual.identity.Platform != "macos" || a.individual.hardwareVersion.Load() != enrollment.HardwareInventoryVersion {
		return nil
	}
	if h == nil {
		return machardware.ErrHardware
	}
	value, err := enrollment.NormalizeHardware(*h)
	if err != nil || value.AgentID != a.individual.identity.Response.DeviceID {
		return errHardwareReport
	}
	// Read at send time so a queued report never retains an expired challenge.
	value.Binding, err = readBinding()
	if err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return errHardwareReport
	}
	defer clear(data)
	msg, err := a.requestBroker("hardware", data, 15*time.Second)
	if err != nil || msg == nil || len(msg.Data) > 1024 {
		return errHardwareReport
	}
	var receipt enrollment.HardwareReceipt
	decoder := json.NewDecoder(bytes.NewReader(msg.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF || receipt.Version != enrollment.HardwareInventoryVersion || !receipt.OK {
		return errHardwareReport
	}
	return nil
}
