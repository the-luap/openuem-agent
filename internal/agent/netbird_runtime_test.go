package agent

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/agent/dsc"
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
)

func TestNativeNetbirdBindingRenewalAndLivePrivateControl(t *testing.T) {
	a, console, _, issuer := nativeRuntimeFixtureWithIssuer(t)
	a.ctx = a.individual.ctx
	a.individual.directory = filepath.Join(t.TempDir(), "identity")
	if err := keyfile.CreateDirectory(a.individual.directory); err != nil {
		t.Fatal(err)
	}
	first, err := a.netbirdBinding("ignored-versioned-release-path", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first.Directory != filepath.Join(a.individual.directory, "netbird-journal") || !first.Identity.Individual || !first.Identity.Valid() {
		t.Fatal("journal did not use native installation identity")
	}
	if runtime.GOOS != "windows" && first.PreparationDirectory != filepath.Join(a.individual.directory, "netbird-preparation") {
		t.Fatal("preparation escaped native individual ownership")
	}
	response := &a.individual.identity.Response
	block, _ := pem.Decode([]byte(response.Certificate))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode([]byte(response.Authority))
	authority, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf.SerialNumber = big.NewInt(3)
	leaf.NotAfter = leaf.NotAfter.Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, leaf, authority, &a.individual.identity.Keys.Certificate.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	response.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	response.ExpiresAt = leaf.NotAfter
	renewed, err := a.netbirdBinding("another-release", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Installation != first.Installation || renewed.Identity.CertificateHash == first.Identity.CertificateHash || renewed.Directory != first.Directory || !renewed.ExpiresAt.Equal(leaf.NotAfter) {
		t.Fatal("renewal reset installation or lost actual certificate identity")
	}
	boot, err := netbirdjournal.ReadBoot()
	if err != nil {
		t.Fatal(err)
	}
	if err = a.openNetbird(renewed, boot); err != nil {
		t.Fatal(err)
	}
	if err = a.netbird.bind(a.NATSConnection); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	control := netbirdcommand.ControlRequest{Version: 1, Identity: renewed.Identity, RequestID: uuid.NewString(), Kind: "state", IssuedAt: now, ExpiresAt: now.Add(time.Second)}
	data, _ := netbirdcommand.EncodeControl(control)
	subject, _ := netbirdcommand.ControlSubject(control.DeviceID)
	msg, err := console.Request(subject, data, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := netbirdcommand.DecodeControlResponse(msg.Data, control)
	if err != nil || r.Outcome != "ok" || r.State.Status != "ready" || r.State.Remaining != netbirdjournal.MaxAttempts {
		t.Fatal("native private subscription did not return live state", err)
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		preparation := control
		preparation.RequestID, preparation.Kind = uuid.NewString(), "preparation-state"
		raw, _ := netbirdcommand.EncodeControl(preparation)
		msg, err := console.Request(subject, raw, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		capability, err := netbirdcommand.DecodeControlResponse(msg.Data, preparation)
		if err != nil || capability.Outcome != "ok" || capability.State != r.State {
			t.Fatal("native preparation was not bound to the same journal", err)
		}
		if keyfile.CheckDirectory(renewed.PreparationDirectory) != nil {
			t.Fatal("native staging directory is not private")
		}
		// A wrong native target must reach the authenticated preparation handler
		// but fail before any HTTP request or native installer can run.
		pkg := packageapi.Package{Schema: 1, ApprovalID: uuid.NewString(), TenantID: control.TenantID, Platform: "linux", Architecture: "arm64", Format: "deb", PackageID: "netbird", Version: "0.78.1", URL: "https://never-request.example.test/netbird.deb", Size: 100, SHA256: strings.Repeat("d", 64)}
		if runtime.GOOS == "linux" {
			pkg.Platform, pkg.Format, pkg.PackageID, pkg.URL = "macos", "pkg", "io.netbird.client", "https://never-request.example.test/netbird.pkg"
		}
		request := netbirdcommand.PreparationRequest{Version: netbirdcommand.PreparationVersion, Identity: control.Identity, RequestID: uuid.NewString(), Revision: strings.Repeat("a", 64), JournalRevision: r.State.Revision, Package: pkg, IssuedAt: now, ExpiresAt: now.Add(10 * time.Second)}
		encoded, err := netbirdcommand.EncodePreparation(request)
		if err != nil {
			t.Fatal(err)
		}
		preparationSubject, _ := netbirdcommand.PreparationSubject(control.DeviceID)
		msg, err = console.Request(preparationSubject, encoded, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		answer, err := netbirdcommand.DecodePreparationResponse(msg.Data, request)
		if err != nil || answer.Outcome != "unavailable" {
			t.Fatal("wrong native target entered preparation", err)
		}
		entries, err := os.ReadDir(renewed.PreparationDirectory)
		if err != nil || len(entries) != 0 {
			t.Fatal("rejected native package left private staging files")
		}
	}
	// Renewal never authorizes controls addressed to the retired certificate.
	old := control
	old.Identity = first.Identity
	old.RequestID = uuid.NewString()
	data, _ = netbirdcommand.EncodeControl(old)
	msg, err = console.Request(subject, data, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = netbirdcommand.DecodeControlResponse(msg.Data, old); err == nil {
		t.Fatal("retired certificate reached journal")
	}
	changed := a.Config
	changed.SiteID = "5"
	a.netbird.verifyConfig(changed)
	if err = a.netbird.bind(a.NATSConnection); err == nil {
		t.Fatal("configuration move retained old authority")
	}
	// Scope change closes and joins the original owner, without deleting history.
	reopened, err := netbirdjournal.Open(renewed.Directory, renewed.Installation, renewed.Identity, boot)
	if err != nil {
		t.Fatal("old owner retained lease after invalidation", err)
	}
	reopened.Close()
	a.Stop()
}

func TestNativeNetbirdRejectsInvalidLocalIdentityAndProfileMutations(t *testing.T) {
	for _, config := range []Config{{}, {UUID: "owned", TenantID: "1", SiteID: "0"}, {UUID: "owned", TenantID: "01", SiteID: "2"}, {UUID: "owned.*", TenantID: "1", SiteID: "2"}, {UUID: "owned", TenantID: "1", SiteID: "+2"}} {
		if _, err := netbirdConfiguredIdentity(config); err == nil {
			t.Fatal("invalid configured identity accepted")
		}
	}
	a, _, _ := nativeRuntimeFixture(t)
	a.individual.directory = filepath.Join(t.TempDir(), "identity")
	if err := keyfile.CreateDirectory(a.individual.directory); err != nil {
		t.Fatal(err)
	}
	if _, err := a.netbirdBinding("", a.individual.identity.Response.ExpiresAt); err == nil {
		t.Fatal("expired native certificate accepted")
	}
	a.Config.SiteID = "5"
	if _, err := a.netbirdBinding("", time.Now()); err == nil {
		t.Fatal("configuration overrode protected site")
	}
	// A profile cannot bypass the managed-command barrier or mark a failed
	// NetBird step as successful in the old profile completion file.
	p := openuem.ProfileConfig{NetBirdConfig: []*openuem.NetbirdTask{{ID: "owned-step", Install: true}}}
	control := &dsc.TaskControl{}
	reports, err := a.ApplyNetBirdConfiguration(p, control, filepath.Join(t.TempDir(), "absent-control.json"))
	if err == nil || len(reports) != 1 || !reports[0].Failed || !strings.Contains(reports[0].StdErr, "reviewed command") || len(control.Success) != 0 {
		t.Fatal("legacy profile mutated or claimed completion")
	}
}

func TestLegacyNetbirdBindingChecksCertificateAndStableScope(t *testing.T) {
	individual, _, _ := nativeRuntimeFixture(t)
	identity := individual.individual.identity
	parent := t.TempDir()
	certPath, keyPath := filepath.Join(parent, "agent.pem"), filepath.Join(parent, "agent.key")
	if err := os.WriteFile(certPath, []byte(identity.Response.Certificate), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(identity.Keys.Certificate)}), 0600); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(identity.Response.Authority))
	authority, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{Config: Config{UUID: "owned-legacy", TenantID: "3", SiteID: "4", AgentCert: certPath, AgentKey: keyPath, NATSServers: "tls://owned-broker.example.test:4222"}, CACert: authority}
	config := filepath.Join(parent, "openuem.ini")
	binding, err := a.netbirdBinding(config, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if binding.Identity.Individual || binding.Identity.CertificateHash != "" || binding.Directory != filepath.Join(parent, "netbird-journal") {
		t.Fatal("legacy installation acquired a false individual identity")
	}
	a.Config.SiteID = "5"
	changed, err := a.netbirdBinding(config, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if changed.Installation == binding.Installation {
		t.Fatal("scope change reused journal ownership")
	}
	if _, err = a.netbirdBinding(config, binding.ExpiresAt); err == nil {
		t.Fatal("expired legacy certificate accepted")
	}
	if err = os.WriteFile(keyPath, []byte("invalid-owned-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = a.netbirdBinding(config, time.Now()); err == nil {
		t.Fatal("invalid certificate key pair accepted")
	}
}
