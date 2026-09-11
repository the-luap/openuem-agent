package windowssoftware

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestNativeWindowsSoftwareBootSession(t *testing.T) {
	if _, err := kernelBootSequence(); err != nil {
		t.Fatal("native shared boot sequence unavailable", err)
	}
	if _, err := readSystemProcessCreation(); err != nil {
		t.Fatal("native System process creation unavailable", err)
	}
	first, err := ReadBootSession()
	if err != nil || !first.Valid() {
		t.Fatal("native kernel boot evidence unavailable", err)
	}
	if os.Getenv("OPENUEM_BOOT_READ_CHILD") == "1" {
		data, _ := json.Marshal(first)
		_, _ = os.Stdout.Write(data)
		os.Exit(0)
	}
	second, err := ReadBootSession()
	if err != nil || first != second {
		t.Fatal("repeated native read changed kernel identity", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestNativeWindowsSoftwareBootSession$")
	command.Env = append(os.Environ(), "OPENUEM_BOOT_READ_CHILD=1")
	data, err := command.Output()
	if err != nil {
		t.Fatal("owned process could not read same kernel session", err)
	}
	var other BootSession
	if len(data) > 256 || json.Unmarshal(data, &other) != nil || other != first || other.After(first) {
		t.Fatal("agent process restart became reboot evidence")
	}
	canonical, _ := json.Marshal(other)
	if !bytes.Equal(data, canonical) {
		t.Fatal("unexpected native helper output")
	}
}
