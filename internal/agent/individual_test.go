package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/commands/report"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
)

const individualFixtureID = "6f73f916-8aaf-4cd1-92e9-c8cbb11028ba"

func TestIndividualModeSelectionRejectsAmbiguousOrIncompleteConfiguration(t *testing.T) {
	for _, mode := range []string{"", "false"} {
		if directory, err := individualDirectory(mode, ""); err != nil || directory != "" {
			t.Fatal("legacy default changed", err)
		}
	}
	for _, tc := range [][2]string{{"true", ""}, {"TRUE", t.TempDir()}, {"", t.TempDir()}, {"false", t.TempDir()}, {"true", "relative"}} {
		if _, err := individualDirectory(tc[0], tc[1]); !errors.Is(err, errIndividualAgent) {
			t.Fatal("ambiguous configuration selected a runtime", err)
		}
	}
	directory := t.TempDir()
	if got, err := individualDirectory("true", directory); err != nil || got != directory {
		t.Fatal("explicit native storage was rejected", err)
	}
}

func TestIndividualINIUsesProtectedScopeWithoutSharedCertificateFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &Agent{individual: &individualRuntime{identity: &enrollmentstore.Identity{Response: enrollment.Response{DeviceID: individualFixtureID, TenantID: 3, SiteID: 4}}, ctx: ctx, cancel: cancel}}
	path := filepath.Join(t.TempDir(), "openuem.ini")
	// No NATS or Certificates sections and no certificate/private-key files exist.
	data := `[Agent]
UUID = untrusted-ini-id
TenantID = 99
SiteID = 99
Enabled = true
ExecuteTaskEveryXMinutes = 5
DefaultFrequency = 15
Debug = false
SFTPPort = 2022
VNCProxyPort = 5900
SFTPDisabled = false
RemoteAssistanceDisabled = false
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.readConfigFile(path); err != nil {
		t.Fatal("individual config required shared credentials", err)
	}
	if a.Config.UUID != individualFixtureID || a.Config.TenantID != "3" || a.Config.SiteID != "4" || a.Config.AgentKey != "" || a.Config.AgentCert != "" || a.Config.CACert != "" || a.Config.SFTPCert != "" || a.Config.NATSServers != "" || a.Config.WebSocketPort != "" {
		t.Fatal("INI values replaced protected enrollment scope")
	}
	if !a.Config.SFTPDisabled || !a.Config.RemoteAssistanceDisabled || a.Config.SFTPPort != "" || a.Config.VNCProxyPort != "" {
		t.Fatal("individual mode enabled an unsupported inbound transport")
	}
	a.Config.SFTPDisabled, a.Config.RemoteAssistanceDisabled = false, false
	a.Config.SFTPPort, a.Config.VNCProxyPort = "2022", "5900"
	a.Config.enforceIndividualTransport()
	if !a.Config.SFTPDisabled || !a.Config.RemoteAssistanceDisabled || a.Config.SFTPPort != "" || a.Config.VNCProxyPort != "" {
		t.Fatal("remote settings reenabled legacy transport")
	}
	if err := a.NewConfigSubscribe(); err != nil {
		t.Fatal("individual mode tried to subscribe to the global config subject", err)
	}
}

func nativeRuntimeFixture(t *testing.T) (*Agent, *nats.Conn, jetstream.JetStream) {
	t.Helper()
	a, worker, js, _ := nativeRuntimeFixtureWithIssuer(t)
	return a, worker, js
}

func nativeRuntimeFixtureWithIssuer(t *testing.T) (*Agent, *nats.Conn, jetstream.JetStream, *ecdsa.PrivateKey) {
	t.Helper()
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if keys.Broker != nil {
			keys.Broker.Wipe()
		}
	})
	public, err := keys.Broker.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	workerKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(workerKey.Wipe)
	workerPublic, err := workerKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := enrollment.DeviceSubjects(individualFixtureID)
	if err != nil {
		t.Fatal(err)
	}
	tlsFixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := tlsFixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(tlsFixture.Certificate())
	tlsFixture.Close()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, JetStream: true, JetStreamMaxStore: 8 << 30, StoreDir: t.TempDir(),
		Websocket: server.WebsocketOpts{Host: "127.0.0.1", Port: -1, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}},
		Nkeys:     []*server.NkeyUser{{Nkey: public, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Allow: policy.Publish}, Subscribe: &server.SubjectPermission{Allow: policy.Subscribe}, Response: &server.ResponsePermission{MaxMsgs: 1, Expires: 15 * time.Minute}}}, {Nkey: workerPublic}},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("isolated broker did not start")
	}
	endpoint := broker.WebsocketURL() + "/agent-channel"
	worker, err := nats.Connect(endpoint, nats.Secure(&tls.Config{RootCAs: roots}), nats.Nkey(workerPublic, workerKey.Sign))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	js, err := jetstream.New(worker)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := openuem.EnsureAgentCommandStream(ctx, js); err != nil {
		t.Fatal("could not provision isolated command stream", err)
	}
	if err := openuem.EnsureAgentCommandConsumer(ctx, js, individualFixtureID); err != nil {
		t.Fatal("could not provision isolated command consumer", err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Isolated individual identity CA"}, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: individualFixtureID}, URIs: []*url.URL{{Scheme: "urn", Opaque: "openuem:agent:" + individualFixtureID}}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &keys.Certificate.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	identity := &enrollmentstore.Identity{Keys: keys, Origin: "https" + strings.TrimSuffix(strings.TrimPrefix(endpoint, "wss"), "/agent-channel"), Response: enrollment.Response{Version: 1, DeviceID: individualFixtureID, TenantID: 3, SiteID: 4, Endpoint: endpoint, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})), Authority: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), ExpiresAt: leaf.NotAfter}}
	lifetime, stop := context.WithCancel(context.Background())
	a := &Agent{individual: &individualRuntime{identity: identity, ctx: lifetime, cancel: stop}}
	a.applyIndividualConfig()
	// The issuer is a different authority from the TLS server. Supplying only
	// system trust must fail rather than trusting the returned identity CA.
	if connection, err := a.connectIndividualBroker(nil); err == nil {
		connection.Close()
		t.Fatal("identity CA replaced server TLS trust")
	}
	a.NATSConnection, err = a.connectIndividualBroker(roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Stop)
	return a, worker, js, caKey
}

func TestIndividualAgentSendsItsActualReportOverWSSAndPrivateSubjects(t *testing.T) {
	a, worker, _ := nativeRuntimeFixture(t)
	var connections sync.WaitGroup
	for range 4 {
		connections.Go(func() {
			connection, err := a.connectIndividualBroker(nil)
			if err != nil || connection != a.NATSConnection {
				t.Error("duplicate connect did not reuse its existing owner", err)
			}
		})
	}
	connections.Wait()
	subject, err := enrollment.RequestSubject(individualFixtureID, "report")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan struct{}, 1)
	_, err = worker.Subscribe(subject, func(message *nats.Msg) {
		if !enrollment.ValidReply(individualFixtureID, message.Reply) {
			t.Error("report used a shared reply inbox")
			return
		}
		var value openuem.AgentReport
		if err := json.Unmarshal(message.Data, &value); err != nil || value.AgentID != individualFixtureID || value.Tenant != "3" || value.Site != "4" {
			t.Error("report lost protected scope", err)
			return
		}
		received <- struct{}{}
		message.Respond(nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	value := &report.Report{AgentReport: openuem.AgentReport{AgentID: individualFixtureID, Tenant: a.Config.TenantID, Site: a.Config.SiteID}}
	if err := a.SendReport(value); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("actual SendReport did not reach the scoped worker")
	}
	if _, err := a.requestBroker("agent.reboot.other", nil, time.Second); !errors.Is(err, errIndividualAgent) {
		t.Fatal("unknown request operation reached the broker", err)
	}
	if err := a.NATSConnection.LastError(); err != nil {
		t.Fatal("runtime attempted a forbidden broker operation", err)
	}
}

func TestIndividualAgentConsumesOnlyItsPreparedQueueAndJoinsShutdown(t *testing.T) {
	a, _, js := nativeRuntimeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	received := make(chan struct{}, 1)
	a.startIndividualConsumer(func(message jetstream.Msg) {
		if message.Subject() != "agent.report."+individualFixtureID || string(message.Data()) != "own command" {
			t.Error("consumer delivered another device's command")
			return
		}
		if err := message.DoubleAck(ctx); err != nil {
			t.Error(err)
		}
		received <- struct{}{}
	})
	if _, err := js.Publish(ctx, "agent.report."+individualFixtureID, []byte("own command")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("individual runtime did not consume its prepared queue")
	}
	if err := a.NATSConnection.LastError(); err != nil {
		t.Fatal("runtime tried to create or broaden its consumer", err)
	}
	stopped := make(chan struct{})
	go func() {
		var stops sync.WaitGroup
		for range 4 {
			stops.Go(a.Stop)
		}
		stops.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("native runtime did not join consumer/broker shutdown")
	}
	if a.individual.identity.Keys != nil {
		t.Fatal("stopped runtime retained its key owner")
	}
	if _, err := a.connectIndividualBroker(nil); !errors.Is(err, errIndividualAgent) {
		t.Fatal("stopped runtime restarted its broker", err)
	}
}

func TestIndividualAgentShutdownCancelsAnOutstandingRequest(t *testing.T) {
	a, worker, _ := nativeRuntimeFixture(t)
	subject, _ := enrollment.RequestSubject(individualFixtureID, "agentconfig")
	entered := make(chan struct{})
	_, err := worker.Subscribe(subject, func(*nats.Msg) { close(entered) })
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := a.requestBroker("agentconfig", []byte(`{}`), 10*time.Minute); result <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach the broker")
	}
	a.Stop()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("shutdown did not preserve cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request retained its ten-minute timeout after shutdown")
	}
}
