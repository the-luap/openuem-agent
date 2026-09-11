package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
)

func TestPackageRequestRejectsForeignOrAmbiguousMessages(t *testing.T) {
	valid := `{"agentid":"owned-device","action":"install","packageid":"Vendor.Product"}`
	for _, data := range []string{
		strings.Replace(valid, "owned-device", "foreign-device", 1),
		strings.Replace(valid, "install", "uninstall", 1),
		strings.Replace(valid, "\"agentid\"", "\"AgentId\"", 1),
		strings.Replace(valid, "{", `{"agentid":"foreign-device",`, 1),
		strings.Replace(valid, "{", `{"unknown":true,`, 1),
		strings.Replace(valid, `"Vendor.Product"`, `null`, 1),
		strings.Replace(valid, `"Vendor.Product"`, `" "`, 1),
		strings.Replace(valid, `"Vendor.Product"`, `["Vendor.Product"]`, 1),
		valid + "{}", "null", "[]", "{", valid + strings.Repeat(" ", 8<<10),
	} {
		if _, err := decodePackageRequest([]byte(data), "owned-device", "install"); err == nil {
			t.Fatalf("accepted %q", data)
		}
	}
	if _, err := decodePackageRequest([]byte(valid), "owned-device", "install"); err != nil {
		t.Fatal(err)
	}
}

func TestPackageResultsAreLocallyProducedAndRetriedForEveryOperation(t *testing.T) {
	for _, operation := range []string{"install", "update", "uninstall"} {
		for _, failed := range []bool{false, true} {
			name := operation + "/success"
			if failed {
				name = operation + "/failure"
			}
			t.Run(name, func(t *testing.T) {
				a := &Agent{ctx: context.Background(), Config: Config{UUID: "owned-device"}}
				action := openuem.DeployAction{AgentId: "owned-device", Action: operation, PackageId: "Vendor.Product", Failed: !failed, Info: "untrusted incoming result", When: time.Now().Add(-time.Hour)}
				data, err := json.Marshal(action)
				if err != nil {
					t.Fatal(err)
				}
				var sent, saved *openuem.DeployAction
				reports, executions := 0, 0
				started := time.Now()
				handler := a.packageHandler(operation, func(gotOperation string, got openuem.DeployAction) (string, string, error) {
					executions++
					if gotOperation != operation || got.AgentId != action.AgentId || got.PackageId != action.PackageId || got.Info != "" || got.Failed || !got.When.IsZero() {
						t.Fatalf("executor received %+v", got)
					}
					if failed {
						return "", "", errors.New("private execution detail")
					}
					return "output", "warning", nil
				}, func(result *openuem.DeployAction) error { copy := *result; sent = &copy; return errors.New("offline") }, func(result openuem.DeployAction) error { saved = &result; return nil }, func() { reports++ })
				handler(&nats.Msg{Subject: "agent." + operation + "package.owned-device", Data: data})
				if executions != 1 || sent == nil || saved == nil || *sent != *saved || sent.Failed != failed || sent.When.Before(started) {
					t.Fatalf("sent %+v saved %+v executions %d", sent, saved, executions)
				}
				if failed {
					if sent.Info == "" || strings.Contains(sent.Info, "private") || reports != 0 {
						t.Fatalf("failure result %+v, reports %d", sent, reports)
					}
				} else if sent.Info != "" || reports != 1 {
					t.Fatalf("success result %+v, reports %d", sent, reports)
				}
			})
		}
	}
}

func TestPackageHandlerDoesNotExecuteMisdirectedOrIndividualRequests(t *testing.T) {
	a := &Agent{ctx: context.Background(), Config: Config{UUID: "owned-device"}}
	handler := a.packageHandler("install", func(string, openuem.DeployAction) (string, string, error) {
		t.Fatal("invalid request executed")
		return "", "", nil
	}, nil, nil, nil)
	data := []byte(`{"agentid":"owned-device","action":"install","packageid":"Vendor.Product"}`)
	handler(&nats.Msg{Subject: "agent.installpackage.foreign-device", Data: data})
	handler(&nats.Msg{Subject: "agent.installpackage.owned-device", Data: []byte(`{"agentid":"foreign-device"}`)})
	a.individual = &individualRuntime{}
	handler(&nats.Msg{Subject: "agent.installpackage.owned-device", Data: data})
	if err := a.InstallPackageSubscribe(); err == nil {
		t.Fatal("individual identity admitted legacy subscription")
	}
}

func TestLegacyBrokerRequestStopsWithServiceContext(t *testing.T) {
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("owned broker did not start")
	}
	connection, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	received := make(chan struct{}, 1)
	if _, err = connection.Subscribe("deployresult", func(*nats.Msg) { received <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	if err = connection.Flush(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &Agent{ctx: ctx, NATSConnection: connection}
	done := make(chan error, 1)
	go func() {
		done <- a.SendDeployResult(&openuem.DeployAction{AgentId: "owned-device", Action: "install", PackageId: "Vendor.Product"})
	}()
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not receive result")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("result waited for the two-minute broker timeout during shutdown")
	}
}
