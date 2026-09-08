package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/commands/report"
)

func TestHardwareCapabilityAndSeparateScopedRPC(t *testing.T) {
	a, worker, _ := nativeRuntimeFixture(t)
	a.individual.identity.Platform = "macos"
	h := &enrollment.HardwareInventory{Version: 1, AgentID: individualFixtureID, Model: "Mac16,1", Serial: "ABCD123456", PlatformUUID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"}
	proof := &enrollment.MacBindingProof{ChallengeID: "12345678-1234-4234-8234-123456789abc", DeviceID: "12345678-1234-4234-8234-123456789abd", Token: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))}
	reads := 0
	read := func() (*enrollment.MacBindingProof, error) { reads++; return proof, nil }
	for _, version := range []int{0, 2, -1} {
		a.setHardwareCapability(version)
		if err := a.sendHardwareUsing(h, read); err != nil || reads != 0 {
			t.Fatal("unsupported worker caused hardware access", err)
		}
	}
	a.setHardwareCapability(1)
	subject, _ := enrollment.RequestSubject(individualFixtureID, "hardware")
	requests, err := worker.SubscribeSync(subject)
	if err != nil {
		t.Fatal(err)
	}
	defer requests.Unsubscribe()
	if err := worker.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	for _, reply := range []string{`{"version":1,"ok":true}`, `{"error":"denied"}`, `{"version":2,"ok":true}`, `{"version":1,"ok":false}`, `{"version":1,"ok":true} {}`, `{"version":1,"ok":true,"extra":true}`} {
		done := make(chan error, 1)
		go func() { done <- a.sendHardwareUsing(h, read) }()
		message, err := requests.NextMsg(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var actual enrollment.HardwareInventory
		if json.Unmarshal(message.Data, &actual) != nil || actual.Binding == nil || *actual.Binding != *proof || actual.AgentID != individualFixtureID || !enrollment.ValidReply(individualFixtureID, message.Reply) {
			t.Fatal("scoped proof report changed")
		}
		if err := message.Respond([]byte(reply)); err != nil {
			t.Fatal(err)
		}
		err = <-done
		if (err == nil) != (reply == `{"version":1,"ok":true}`) {
			t.Fatal("invalid hardware receipt accepted", err)
		}
	}
	if h.Binding != nil {
		t.Fatal("send retained the proof in a reusable report")
	}
	if err := a.sendHardwareUsing(h, func() (*enrollment.MacBindingProof, error) { return nil, errors.New("unavailable") }); err == nil {
		t.Fatal("binding read failure ignored")
	}
	h.Binding = proof
	data, err := json.Marshal(&report.Report{AgentReport: openuem.AgentReport{AgentID: individualFixtureID}, Hardware: h})
	if err != nil || bytes.Contains(data, []byte(proof.Token)) || bytes.Contains(data, []byte("hardware")) {
		t.Fatal("legacy report disclosed binding", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var legacy openuem.AgentReport
	if decoder.Decode(&legacy) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("legacy worker can no longer decode inventory")
	}
	a.individual.identity.Platform = "windows"
	a.setHardwareCapability(1)
	before := reads
	if err := a.sendHardwareUsing(h, read); err != nil || reads != before {
		t.Fatal("Windows runtime requested Mac evidence")
	}
}

func TestIndividualInventoryErrorDoesNotBecomeSuccessfulReport(t *testing.T) {
	a, worker, _ := nativeRuntimeFixture(t)
	subject, _ := enrollment.RequestSubject(individualFixtureID, "report")
	sub, err := worker.Subscribe(subject, func(msg *nats.Msg) { _ = msg.Respond([]byte(`{"error":"agent request denied"}`)) })
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := worker.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := a.SendReport(&report.Report{AgentReport: openuem.AgentReport{AgentID: individualFixtureID}}); err == nil {
		t.Fatal("denied report marked successful")
	}
	if err := sub.Unsubscribe(); err != nil {
		t.Fatal(err)
	}
	sub, err = worker.Subscribe(subject, func(msg *nats.Msg) { _ = msg.Respond([]byte("Report received!")) })
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := worker.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := a.SendReport(&report.Report{AgentReport: openuem.AgentReport{AgentID: individualFixtureID}}); err != nil {
		t.Fatal("existing worker receipt was rejected", err)
	}
}
