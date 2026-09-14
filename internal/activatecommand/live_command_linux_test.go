package activatecommand

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/linuxservice"
	"github.com/open-uem/openuem-agent/internal/localready"
)

const liveCommandDirectory = "/fixture/enrolled-identity"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		os.Exit(serveOwnedActivationCommand())
	}
	os.Exit(m.Run())
}

// The canonical service launches this test binary only inside the owned RAM
// guest. Readiness uses keys loaded by the real native encrypted store. This
// helper does not represent broker initialization or inventory delivery.
func serveOwnedActivationCommand() int {
	if len(os.Args) != 4 || os.Args[0] != "/fixture/activatecommand.test" || os.Args[2] != "-identity-directory" || os.Args[3] != liveCommandDirectory || ownedActivationGuest() != nil {
		return 1
	}
	store, err := enrollmentstore.Open(liveCommandDirectory)
	if err != nil {
		return 1
	}
	defer store.Close()
	identity, err := store.Load()
	if err != nil {
		return 1
	}
	defer identity.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	server, err := localready.Listen(ctx, liveCommandDirectory, liveCommandReadiness(identity), identity.Keys.Broker)
	if err != nil {
		return 1
	}
	defer server.Close()
	if server.MarkReady() != nil {
		return 1
	}
	<-ctx.Done()
	if server.Close() != nil {
		return 1
	}
	return 0
}

func liveCommandReadiness(identity *enrollmentstore.Identity) localready.Identity {
	return localready.Identity{DeviceID: identity.Response.DeviceID, TenantID: identity.Response.TenantID, SiteID: identity.Response.SiteID,
		ReleaseDigest: identity.ReleaseDigest, AgentSize: identity.AgentSize, AgentSHA256: identity.AgentSHA256, ExpiresAt: identity.Response.ExpiresAt}
}

func TestLinuxLiveActivationCommand(t *testing.T) {
	liveActivationGuest(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	// Provision the synthetic guest's host key before opening the production
	// store. Production enrollment deliberately does not provision that key.
	if err := exec.CommandContext(ctx, "/usr/bin/systemd-creds", "setup").Run(); err != nil {
		t.Fatal("could not provision the owned guest credential key", err)
	}
	defer os.RemoveAll(liveCommandDirectory)
	defer os.RemoveAll(linuxservice.ConfigurationDirectory)
	defer os.RemoveAll(linuxservice.LogDirectory)
	bootstrap, claims, issuer := enrollLiveCommandIdentity(t, ctx)
	// Activation must work solely from its completed local identity, even when
	// the issuer is no longer available. No second claim can be required.
	issuer.Close()
	before := liveCommandRecords(t)
	store, err := enrollmentstore.Open(liveCommandDirectory)
	if err != nil {
		t.Fatal("completed native store could not reopen", err)
	}
	defer store.Close()
	identity, err := store.Load()
	if err != nil {
		t.Fatal("completed native identity could not reopen", err)
	}
	defer identity.Close()
	public, err := identity.Keys.Broker.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := store.Checkpoint()
	if err != nil || checkpoint.Sequence != bootstrap.ReleaseSequence || checkpoint.Digest != bootstrap.ReleaseDigest || identity.Platform != "linux" || identity.Architecture != runtime.GOARCH || identity.AgentSize != bootstrap.AgentSize || identity.AgentSHA256 != bootstrap.AgentSHA256 {
		t.Fatal("native enrollment lost its release or running executable binding", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		command := exec.CommandContext(cleanupCtx, "/fixture/linuxservice.test", "-test.v", "-test.count=1", "-test.timeout=10s", "-test.run=^TestLinuxOwnedActivationCommandCleanup$")
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("owned command cleanup failed: %v\n%s", err, output)
		} else if !bytes.Contains(output, []byte("--- PASS: TestLinuxOwnedActivationCommandCleanup")) {
			t.Error("owned command cleanup did not execute")
		}
	}()
	result, err := Run(ctx, Options{IdentityDirectory: liveCommandDirectory})
	want := Result{Registered: true, Running: true, DeviceID: fixtureDeviceID, TenantID: 3, SiteID: 4}
	if err != nil || result != want {
		t.Fatal("public activation did not start the enrolled native process", err, result)
	}
	if err := localready.Probe(ctx, liveCommandDirectory, liveCommandReadiness(identity), public); err != nil {
		t.Fatal("public activation close lost the running service", err)
	}
	// Retry through the public parser as well, with no injected dependencies.
	var output, diagnostics bytes.Buffer
	handled, status := Handle(ctx, []string{"activate", "-identity-directory", liveCommandDirectory}, &output, &diagnostics)
	var again Result
	if !handled || status != 0 || diagnostics.Len() != 0 || json.Unmarshal(output.Bytes(), &again) != nil || again != want {
		t.Fatal("public command did not reuse the admitted native service", status)
	}
	data, err := os.ReadFile(filepath.Join(linuxservice.ConfigurationDirectory, "openuem.ini"))
	if err != nil || !validConfiguration(data, identity) {
		t.Fatal("public activation did not preserve enrollment-bound operational configuration", err)
	}
	if claims.Load() != 1 || !reflect.DeepEqual(before, liveCommandRecords(t)) {
		t.Fatal("activation changed completed encrypted identity records or repeated enrollment")
	}
}

// The fixture supplies an explicitly authorized bootstrap, matching the public
// activation precondition of completed enrollment. Signed package/bootstrap
// admission is exercised separately by the native enrollcommand fixtures.
func enrollLiveCommandIdentity(t *testing.T, ctx context.Context) (enrollmentstore.Bootstrap, *atomic.Int32, *httptest.Server) {
	t.Helper()
	image, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, image)
	image.Close()
	if err != nil || size <= 0 {
		t.Fatal("could not bind the owned running image", err)
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	bootstrap := enrollmentstore.Bootstrap{Invitation: base64.RawURLEncoding.EncodeToString(token[:]), Platform: "linux", Architecture: runtime.GOARCH,
		DeviceName: "Owned activation fixture", TenantID: 3, SiteID: 4, ReleaseSequence: 42, ReleaseDigest: strings.Repeat("a", 64), AgentSize: size, AgentSHA256: hex.EncodeToString(hash.Sum(nil))}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Owned activation fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	claims := new(atomic.Int32)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims.Add(1) != 1 || r.Method != "POST" || r.URL.Path != "/enroll/desktop/"+bootstrap.Invitation+"/claim" {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		var request enrollment.Request
		decoder := json.NewDecoder(io.LimitReader(r.Body, 32<<10))
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		proof, err := enrollment.Validate(request)
		if err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: fixtureDeviceID}, URIs: []*url.URL{{Scheme: "urn", Opaque: "openuem:agent:" + fixtureDeviceID}}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, proof.CertificateKey, key)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollment.Response{Version: 1, DeviceID: fixtureDeviceID, TenantID: 3, SiteID: 4, Endpoint: "wss://" + r.Host + "/agent-channel", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Authority: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})), ExpiresAt: leaf.NotAfter})
	}))
	t.Cleanup(server.Close)
	bootstrap.Origin = server.URL
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	store, err := enrollmentstore.Open(liveCommandDirectory)
	if err != nil {
		t.Fatal("could not open the owned native encrypted store", err)
	}
	defer store.Close()
	identity, err := store.Enroll(ctx, bootstrap, roots)
	if err != nil {
		t.Fatal("owned native enrollment failed", err)
	}
	identity.Close()
	if claims.Load() != 1 {
		t.Fatal("owned enrollment did not make exactly one claim")
	}
	return bootstrap, claims, server
}

func liveCommandRecords(t *testing.T) map[string][sha256.Size]byte {
	t.Helper()
	directory := filepath.Join(liveCommandDirectory, "credentials-v1")
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) == 0 {
		t.Fatal("native encrypted enrollment records are missing", err)
	}
	result := make(map[string][sha256.Size]byte)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal("could not fingerprint owned encrypted record", err)
		}
		result[entry.Name()] = sha256.Sum256(data)
		clear(data)
	}
	return result
}
