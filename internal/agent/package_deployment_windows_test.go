//go:build windows

package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-agent/internal/agent/dsc"
	"github.com/open-uem/wingetcfg/wingetcfg"
)

func TestNativeWindowsPackageShutdownJoinsResultAndClosesAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &Agent{ctx: ctx, cancel: cancel, Config: Config{UUID: "owned-device"}}
	started, sending, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var executions, persisted atomic.Int32
	handler := a.packageHandler("uninstall", func(string, openuem.DeployAction) (string, string, error) {
		executions.Add(1)
		close(started)
		<-ctx.Done()
		return "", "interrupted", ctx.Err()
	}, func(result *openuem.DeployAction) error {
		if !result.Failed || result.Info != "interrupted" || result.When.IsZero() {
			t.Errorf("interrupted result = %+v", result)
		}
		close(sending)
		<-release
		return errors.New("offline")
	}, func(openuem.DeployAction) error { persisted.Add(1); return nil }, func() { t.Error("interrupted command triggered report") })
	msg := &nats.Msg{Subject: "agent.uninstallpackage.owned-device", Data: []byte(`{"agentid":"owned-device","action":"uninstall","packageid":"Vendor.Product"}`)}
	done := make(chan struct{})
	go func() { handler(msg); close(done) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("command did not start")
	}
	stopped := make(chan struct{})
	go func() { a.Stop(); close(stopped) }()
	select {
	case <-sending:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not cancel command")
	}
	handler(msg)
	select {
	case <-stopped:
		t.Error("shutdown returned before result persistence")
	default:
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not join result persistence")
	}
	<-done
	if executions.Load() != 1 || persisted.Load() != 1 {
		t.Fatalf("executions %d, persisted %d", executions.Load(), persisted.Load())
	}
}

func TestNativeWindowsPackageProfileRejectsInvalidDataBeforeExecution(t *testing.T) {
	a := &Agent{}
	for _, resource := range []*wingetcfg.WinGetResource{nil,
		{Settings: map[string]any{"Ensure": "Present", "id": 42}},
		{Settings: map[string]any{"Ensure": "Absent", "id": "Vendor.Product", "uselatest": "false"}},
		{Settings: map[string]any{"Ensure": "Absent", "id": "Vendor.Product", "version": true}},
		{Settings: map[string]any{"Ensure": "Present", "id": "Vendor.Product", "source": "foreign"}},
	} {
		if report, err := a.PackageManagementTask(resource, "", &dsc.TaskControl{}, false); err == nil || report != nil {
			t.Fatalf("invalid profile result: %+v, %v", report, err)
		}
	}
	resource := &wingetcfg.WinGetResource{Settings: map[string]any{"Ensure": "Present", "id": "Vendor.Product"}}
	if report, err := a.PackageManagementTask(resource, "", nil, false); err == nil || report != nil {
		t.Fatalf("nil task control: %+v, %v", report, err)
	}
	cfg := wingetcfg.WinGetCfg{Properties: wingetcfg.WinGetProperties{Resources: []*wingetcfg.WinGetResource{nil}}}
	if reports, err := a.RunTasks(cfg, 1, "", &dsc.TaskControl{}, false); err == nil || reports != nil {
		t.Fatalf("nil resource list: %+v, %v", reports, err)
	}
}
