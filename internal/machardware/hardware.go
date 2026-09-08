// Package machardware parses bounded hardware observations without running
// commands during tests or treating serial numbers as enrollment credentials.
package machardware

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
)

const MaxHardwareBytes = 1 << 20

var ErrHardware = errors.New("Mac hardware inventory is unavailable")

type Snapshot struct {
	Computer         openuem.Computer
	PlatformUUID     string
	ProvisioningUDID string
}

func Parse(data []byte) (Snapshot, error) {
	var value struct {
		Hardware []struct {
			Model            string          `json:"machine_model"`
			Serial           string          `json:"serial_number"`
			CPU              string          `json:"cpu_type"`
			Chip             string          `json:"chip_type"`
			Cores            json.RawMessage `json:"number_processors"`
			Memory           string          `json:"physical_memory"`
			UUID             string          `json:"platform_UUID"`
			ProvisioningUDID string          `json:"provisioning_UDID"`
		} `json:"SPHardwareDataType"`
	}
	if len(data) == 0 || len(data) > MaxHardwareBytes || json.Unmarshal(data, &value) != nil || len(value.Hardware) != 1 {
		return Snapshot{}, ErrHardware
	}
	h := value.Hardware[0]
	if h.Model == "" {
		return Snapshot{}, ErrHardware
	}
	cpu := h.CPU
	if cpu == "" {
		cpu = h.Chip
	}
	return Snapshot{Computer: openuem.Computer{Manufacturer: "Apple", Model: h.Model, Serial: h.Serial, Processor: cpu, ProcessorCores: cores(h.Cores), Memory: memoryMB(h.Memory)}, PlatformUUID: h.UUID, ProvisioningUDID: h.ProvisioningUDID}, nil
}

func (s Snapshot) Inventory(agentID string) (enrollment.HardwareInventory, error) {
	return enrollment.NormalizeHardware(enrollment.HardwareInventory{Version: enrollment.HardwareInventoryVersion, AgentID: agentID, Model: s.Computer.Model, Serial: s.Computer.Serial, PlatformUUID: s.PlatformUUID, ProvisioningUDID: s.ProvisioningUDID})
}

func cores(raw json.RawMessage) int64 {
	var text string
	if json.Unmarshal(raw, &text) != nil {
		text = string(raw)
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value <= 0 || value > 4096 {
		return 0
	}
	return value
}

// Preserve the existing desktop inventory contract: memory is measured in MB.
func memoryMB(text string) uint64 {
	parts := strings.Fields(text)
	if len(parts) != 2 {
		return 0
	}
	value, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || value == 0 || value > 1<<30 {
		return 0
	}
	switch parts[1] {
	case "GB":
		return value * 1024
	case "MB":
		return value
	default:
		return 0
	}
}
