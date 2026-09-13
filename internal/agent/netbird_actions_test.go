package agent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-agent/internal/commands/netbird"
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
	a := &Agent{Config: Config{UUID: "owned-netbird-device"}, NATSConnection: connection}
	for _, subscribe := range []func() error{a.RegisterNetBirdSubscribe, a.SwitchProfileNetBirdSubscribe, a.NetBirdUpSubscribe, a.NetBirdDownSubscribe} {
		if err := subscribe(); err != nil {
			t.Fatal(err)
		}
	}
	if err := connection.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"register", "switchprofile", "up", "down"} {
		for _, data := range []string{"{", `{"management_url":"http://invalid.example.test"}`, `{"management_url":"https://example.test","management_url":"https://other.test"}`, `{"management_url":"https://example.test","profile":null}`} {
			message, err := connection.Request("agent.netbird."+operation+".owned-netbird-device", []byte(data), 2*time.Second)
			if err != nil {
				t.Fatalf("%s did not return a rejection: %v", operation, err)
			}
			var result openuem.Netbird
			if err := json.Unmarshal(message.Data, &result); err != nil {
				t.Fatal(err)
			}
			if result.Error != netbird.ErrInvalidAction.Error() || result.Installed {
				t.Fatalf("%s did not reject safely", operation)
			}
		}
	}
}
