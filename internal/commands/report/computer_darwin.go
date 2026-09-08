//go:build darwin

package report

import (
	"bytes"
	"context"
	"github.com/open-uem/openuem-agent/internal/machardware"
	"io"
	"log"
	"os/exec"
	"time"
)

func (r *Report) getComputerInfo(debug bool) error {
	if debug {
		log.Println("[DEBUG]: computer system info has been requested")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/system_profiler", "-json", "SPHardwareDataType")
	var output bytes.Buffer
	cmd.Stdout = &hardwareOutput{buffer: &output}
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return machardware.ErrHardware
	}
	snapshot, err := machardware.Parse(output.Bytes())
	if err != nil {
		return err
	}
	r.Computer = snapshot.Computer
	r.Computer.ProcessorArch = getMacOSArch()
	r.Hardware = nil
	if hardware, err := snapshot.Inventory(r.AgentID); err == nil {
		r.Hardware = &hardware
	}
	return nil
}

type hardwareOutput struct{ buffer *bytes.Buffer }

func (w *hardwareOutput) Write(data []byte) (int, error) {
	if w.buffer.Len()+len(data) > machardware.MaxHardwareBytes {
		return 0, machardware.ErrHardware
	}
	return w.buffer.Write(data)
}
