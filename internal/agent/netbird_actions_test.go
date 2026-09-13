package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
)

func TestNetbirdSubscriptionsRejectInvalidRequests(t *testing.T) {
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &Agent{ctx: ctx, Config: Config{UUID: "owned-netbird-device"}, NATSConnection: connection}
	for _, subscribe := range []func() error{a.InstallNetBirdSubscribe, a.UninstallNetBirdSubscribe, a.RegisterNetBirdSubscribe, a.SwitchProfileNetBirdSubscribe, a.NetBirdUpSubscribe, a.NetBirdDownSubscribe, a.RefreshNetBirdSubscribe} {
		if err := subscribe(); err != nil {
			t.Fatal(err)
		}
	}
	if err := connection.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"install", "uninstall", "register", "switchprofile", "up", "down"} {
		for _, data := range []string{"", "{", `{"management_url":"https://example.test"}`, `{"management_url":"https://example.test","key":"private-owned-key"}`, `{"management_url":"http://invalid.example.test"}`, `{"management_url":"https://example.test","management_url":"https://other.test"}`, `{"management_url":"https://example.test","profile":null}`} {
			message, err := connection.Request("agent.netbird."+operation+".owned-netbird-device", []byte(data), 2*time.Second)
			if err != nil {
				t.Fatalf("%s did not return a rejection: %v", operation, err)
			}
			var result openuem.Netbird
			if err := json.Unmarshal(message.Data, &result); err != nil {
				t.Fatal(err)
			}
			if result.Error != errNetbirdLegacy.Error() || result.Installed {
				t.Fatalf("%s did not reject safely", operation)
			}
		}
	}
	cancel()
	for operation, body := range map[string]string{
		"up":            `{"management_url":"https://example.test"}`,
		"down":          `{"management_url":"https://example.test"}`,
		"register":      `{"management_url":"https://example.test","key":"owned-key"}`,
		"switchprofile": `{"management_url":"https://example.test","profile":"owned-profile"}`,
		"refresh":       "",
	} {
		message, err := connection.Request("agent.netbird."+operation+".owned-netbird-device", []byte(body), 2*time.Second)
		if err != nil {
			t.Fatal("stopped service did not reject NetBird command", err)
		}
		var result openuem.Netbird
		if err := json.Unmarshal(message.Data, &result); err != nil {
			t.Fatal(err)
		}
		if result.Error == "" || result.Installed {
			t.Fatal("stopped service accepted a NetBird action or observation")
		}
	}
}
