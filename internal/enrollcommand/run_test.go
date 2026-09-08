package enrollcommand

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
)

func TestMain(m *testing.M) {
	if handled, code := packagesignature.HandleHelper(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

type commandFixture struct {
	options        Options
	roots          *x509.CertPool
	server         *httptest.Server
	config         bootstrap.Config
	release        *artifacts.Verified
	releaseKey     ed25519.PrivateKey
	bootstrapKey   ed25519.PrivateKey
	packageBytes   []byte
	agentBytes     []byte
	configOverride []byte
	beforeConfig   func()
	mu             sync.Mutex
	requests       []string
	claimBinding   string
	issued         *enrollment.Response
	ca             *x509.Certificate
	caKey          *ecdsa.PrivateKey
}

func newCommandFixture(t *testing.T) *commandFixture {
	t.Helper()
	public, releaseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, configKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "private-input")
	if err := keyfile.CreateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	f := &commandFixture{releaseKey: releaseKey, bootstrapKey: configKey, packageBytes: []byte("isolated installer bytes; never executed"), agentBytes: []byte("separate installed executable bytes")}
	platform := "windows"
	if runtime.GOOS == "darwin" {
		platform = "macos"
	}
	f.config = bootstrap.Config{Schema: 1, Organization: "Isolated organization", Site: "Isolated site", TenantID: 3, SiteID: 4, Invitation: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), Platform: platform, Architecture: runtime.GOARCH}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.server.EnableHTTP2 = true
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	f.config.Origin = f.server.URL
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.server.Certificate())
	f.options = Options{Origin: f.server.URL, TenantID: 3, SiteID: 4, InvitationFile: filepath.Join(directory, "invitation"), ReleaseKeysFile: filepath.Join(directory, "release-public.pem"), IdentityDirectory: filepath.Join(directory, "identity"), StagingDirectory: filepath.Join(directory, "staging"), AcceptManagement: true}
	if err := keyfile.Create(f.options.InvitationFile, []byte(f.config.Invitation+"\n")); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Create(f.options.ReleaseKeysFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	f.signRelease(t)
	f.caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Isolated native enrollment issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true}
	der, err = x509.CreateCertificate(rand.Reader, ca, ca, &f.caKey.PublicKey, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	f.ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(releaseKey); clear(configKey) })
	return f
}

func (f *commandFixture) signRelease(t *testing.T) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	digest, agentDigest := sha256.Sum256(f.packageBytes), sha256.Sum256(f.agentBytes)
	format := "exe"
	if f.config.Platform == "macos" {
		format = "pkg"
	}
	envelope, err := artifacts.Sign(artifacts.Manifest{Schema: 1, Sequence: 42, Version: "0.12.0", PublishedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour), Artifacts: []artifacts.Artifact{{Platform: f.config.Platform, Architecture: f.config.Architecture, Format: format, Filename: "openuem-agent-0.12.0-" + f.config.Platform + "-" + f.config.Architecture + "." + format, Size: int64(len(f.packageBytes)), SHA256: hex.EncodeToString(digest[:]), AgentSize: int64(len(f.agentBytes)), AgentSHA256: hex.EncodeToString(agentDigest[:])}}}, f.releaseKey, now)
	if err != nil {
		t.Fatal(err)
	}
	f.release, err = artifacts.Verify(envelope, []ed25519.PublicKey{f.releaseKey.Public().(ed25519.PublicKey)}, now, artifacts.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	f.config.ReleaseEnvelope, f.config.ReleaseDigest = envelope, f.release.Digest()
	f.config.IssuedAt, f.config.ExpiresAt = now, now.Add(time.Hour)
}

func (f *commandFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	if r.ProtoMajor != 2 || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Referer") != "" {
		http.Error(w, "invalid transport", 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/enroll/desktop/bootstrap-keys":
		data, _ := bootstrap.MarshalOriginKeys(f.options.Origin, []ed25519.PublicKey{f.bootstrapKey.Public().(ed25519.PublicKey)})
		w.Write(data)
	case strings.HasSuffix(r.URL.Path, "/configuration"):
		if f.beforeConfig != nil {
			f.beforeConfig()
		}
		data := f.configOverride
		if data == nil {
			data, _ = bootstrap.Sign(f.config, f.bootstrapKey, time.Now())
		}
		w.Write(data)
	case strings.HasPrefix(r.URL.Path, "/enroll/desktop/releases/"):
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(f.packageBytes)
	case strings.HasSuffix(r.URL.Path, "/claim"):
		var request enrollment.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid claim", 400)
			return
		}
		proof, err := enrollment.Validate(request)
		if err != nil || request.Invitation != f.config.Invitation {
			http.Error(w, "invalid claim", 400)
			return
		}
		if f.issued != nil {
			if proof.KeyBinding != f.claimBinding {
				http.Error(w, "changed keys", 409)
				return
			}
			json.NewEncoder(w).Encode(f.issued)
			return
		}
		f.claimBinding = proof.KeyBinding
		now := time.Now().UTC().Truncate(time.Second)
		id := "6f73f916-8aaf-4cd1-92e9-c8cbb11028ba"
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{{Scheme: "urn", Opaque: "openuem:agent:" + id}}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, proof.CertificateKey, f.caKey)
		if err != nil {
			http.Error(w, "isolated issuance failed", 500)
			return
		}
		f.issued = &enrollment.Response{Version: 1, DeviceID: id, TenantID: f.config.TenantID, SiteID: f.config.SiteID, Endpoint: "wss" + strings.TrimPrefix(f.options.Origin, "https") + "/agent-channel", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Authority: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})), ExpiresAt: leaf.NotAfter}
		json.NewEncoder(w).Encode(f.issued)
	default:
		http.NotFound(w, r)
	}
}

type fixtureFile struct {
	data     []byte
	agent    bool
	checks   int
	closed   bool
	closeErr error
}

func (f *fixtureFile) Verify(ctx context.Context, v *bootstrap.Verified, checkpoint artifacts.Checkpoint) error {
	f.checks++
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := v.ValidAt(time.Now(), checkpoint); err != nil {
		return err
	}
	if f.closed {
		return errors.New("closed fixture")
	}
	if f.agent {
		return v.VerifyAgent(bytes.NewReader(f.data))
	}
	return v.VerifyPackage(bytes.NewReader(f.data))
}
func (f *fixtureFile) Close() error { f.closed = true; return f.closeErr }

type fixtureStore struct {
	checkpoint artifacts.Checkpoint
	err        error
	checks     int
	enrolls    int
	closed     bool
	before     func()
}

func (s *fixtureStore) Checkpoint() (artifacts.Checkpoint, error) {
	s.checks++
	return s.checkpoint, s.err
}
func (s *fixtureStore) Close() error { s.closed = true; return nil }
func (s *fixtureStore) EnrollInstalled(ctx context.Context, v *bootstrap.Verified, name string, roots *x509.CertPool, admit func(context.Context) error) (*enrollmentstore.Identity, error) {
	s.enrolls++
	if s.before != nil {
		s.before()
	}
	if err := admit(ctx); err != nil {
		return nil, err
	}
	c := v.Config()
	return &enrollmentstore.Identity{Response: enrollment.Response{DeviceID: "isolated-public-identity", TenantID: c.TenantID, SiteID: c.SiteID}, ReleaseDigest: c.ReleaseDigest}, nil
}

func (f *commandFixture) dependencies(t *testing.T, s *fixtureStore, executable, staged *fixtureFile) dependencies {
	t.Helper()
	return dependencies{
		platform: f.config.Platform, architecture: f.config.Architecture, roots: f.roots,
		openExecutable: func() (retainedFile, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.requests) != 0 {
				t.Error("executable was not retained before network access")
			}
			return executable, nil
		},
		openStore: func(string) (stateStore, error) { return s, nil },
		stage: func(ctx context.Context, v *bootstrap.Verified, c *enrollment.HTTPClient, path string, checkpoint artifacts.Checkpoint) (retainedFile, error) {
			var downloaded bytes.Buffer
			if err := v.DownloadPackage(ctx, c, &downloaded); err != nil {
				return nil, err
			}
			staged.data = downloaded.Bytes()
			return staged, nil
		},
	}
}

func TestCommandBindsConsentRequestedScopeAndIndependentReleaseTrust(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*commandFixture)
		want   error
	}{
		{"valid", func(*commandFixture) {}, nil},
		{"consent", func(f *commandFixture) { f.options.AcceptManagement = false }, ErrOptions},
		{"invitation", func(f *commandFixture) {
			f.config.Invitation = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{18}, 32))
		}, ErrScope},
		{"organization", func(f *commandFixture) { f.config.TenantID++ }, ErrScope},
		{"site", func(f *commandFixture) { f.config.SiteID++ }, ErrScope},
		{"origin", func(f *commandFixture) { f.config.Origin = "https://other.example.test" }, ErrConfiguration},
		{"signature", func(f *commandFixture) { f.configOverride = []byte(`{"untrusted":"fixture"}`) }, ErrConfiguration},
		{"untrusted release", func(f *commandFixture) {
			_, f.releaseKey, _ = ed25519.GenerateKey(rand.Reader)
			f.signRelease(t)
		}, ErrConfiguration},
		{"executable", func(f *commandFixture) { f.agentBytes = []byte("changed installed image") }, ErrExecutable},
		{"download", func(f *commandFixture) { f.packageBytes = []byte("changed installer") }, ErrPackage},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCommandFixture(t)
			test.change(f)
			s := &fixtureStore{}
			executable := &fixtureFile{data: f.agentBytes, agent: true}
			staged := &fixtureFile{}
			result, err := run(context.Background(), f.options, f.dependencies(t, s, executable, staged))
			if !errors.Is(err, test.want) {
				t.Fatal("unexpected admission outcome", err, test.want)
			}
			if test.want == nil {
				if !result.IdentityReady || result.TenantID != 3 || result.SiteID != 4 || result.ReleaseDigest != f.release.Digest() || s.checks != 2 || s.enrolls != 1 || executable.checks != 2 || staged.checks != 1 || !staged.closed {
					t.Fatal("verified flow did not retain and recheck its inputs", result)
				}
			} else if result.IdentityReady || s.enrolls != 0 {
				t.Fatal("rejected input reached identity enrollment")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if test.want == ErrOptions {
				if len(f.requests) != 0 || executable.closed || s.closed {
					t.Error("missing consent touched native state or the network")
				}
			} else if !executable.closed || !s.closed {
				t.Error("opened native resources were not closed")
			}
			if test.want == ErrScope && len(f.requests) != 2 {
				t.Error("scope mismatch reached installer download")
			}
		})
	}
}

func TestCommandRechecksNativeInputsAndPreservesCleanupOutcome(t *testing.T) {
	for _, mode := range []string{"checkpoint", "changed staged bytes", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			f := newCommandFixture(t)
			s := &fixtureStore{}
			executable := &fixtureFile{data: f.agentBytes, agent: true}
			staged := &fixtureFile{}
			want := ErrPackage
			s.before = func() {
				switch mode {
				case "changed staged bytes":
					staged.data[0] ^= 1
				case "cleanup":
					staged.closeErr = errors.New("isolated cleanup detail")
				}
			}
			deps := f.dependencies(t, s, executable, staged)
			if mode == "checkpoint" {
				stage := deps.stage
				deps.stage = func(ctx context.Context, v *bootstrap.Verified, c *enrollment.HTTPClient, path string, checkpoint artifacts.Checkpoint) (retainedFile, error) {
					p, err := stage(ctx, v, c, path, checkpoint)
					s.checkpoint = artifacts.Checkpoint{Sequence: 43, Digest: strings.Repeat("b", 64)}
					return p, err
				}
				want = ErrExecutable
			}
			if mode == "cleanup" {
				want = ErrCleanup
			}
			result, err := run(context.Background(), f.options, deps)
			if !errors.Is(err, want) || result.IdentityReady != (mode == "cleanup") || !executable.closed || !staged.closed || !s.closed {
				t.Fatal("native recheck or cleanup outcome was lost", result, err)
			}
		})
	}
}

func TestCommandCancellationAndStorageFailurePrecedeTheNetwork(t *testing.T) {
	for _, mode := range []string{"cancel", "checkpoint", "no system TLS trust"} {
		t.Run(mode, func(t *testing.T) {
			f := newCommandFixture(t)
			s := &fixtureStore{}
			e := &fixtureFile{data: f.agentBytes, agent: true}
			deps := f.dependencies(t, s, e, &fixtureFile{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := ErrConfiguration
			switch mode {
			case "cancel":
				cancel()
				want = context.Canceled
			case "checkpoint":
				s.err = enrollmentstore.ErrUnavailable
				want = ErrStorage
			case "no system TLS trust":
				deps.roots = nil
			}
			if _, err := run(ctx, f.options, deps); !errors.Is(err, want) || s.enrolls != 0 {
				t.Fatal("invalid prerequisite reached enrollment", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.requests) != 0 {
				t.Fatal("invalid prerequisite sent an HTTPS request")
			}
		})
	}
}

// This integration uses the real installed test executable, real WinTrust and
// machine DPAPI. The licensed Go fixture is verified but never executed. macOS
// positive notarized-package acceptance requires the real release credentials;
// other tests exercise its unsigned-package rejection without changing OS trust.
func TestWindowsCommandWithNativeExecutablePackageAndProtectedEnrollment(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows native integration")
	}
	f := newCommandFixture(t)
	var err error
	f.packageBytes, err = os.ReadFile(filepath.Join("..", "packagesignature", "testdata", "ev-signed-file.exe"))
	if err != nil {
		t.Fatal(err)
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f.agentBytes, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.signRelease(t)
	deps := nativeDependencies()
	deps.roots = f.roots // Only this isolated HTTPS server is additionally trusted.
	result, err := run(context.Background(), f.options, deps)
	if err != nil || !result.IdentityReady {
		t.Fatal("native verified enrollment failed", err)
	}
	store, err := enrollmentstore.Open(f.options.IdentityDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identity, err := store.Load()
	if err != nil {
		t.Fatal("native protected identity was not readable", err)
	}
	defer identity.Close()
	if identity.Response.DeviceID != result.DeviceID || identity.ReleaseDigest != f.release.Digest() {
		t.Fatal("native result differs from persisted identity")
	}
	again, err := run(context.Background(), f.options, deps)
	if err != nil || again != result {
		t.Fatal("native repeated command did not return the same identity", err)
	}
	f.mu.Lock()
	claims := 0
	for _, request := range f.requests {
		if strings.HasSuffix(request, "/claim") {
			claims++
		}
	}
	f.mu.Unlock()
	if claims != 1 {
		t.Fatal("ready identity consumed another claim", claims)
	}
	entries, err := os.ReadDir(f.options.StagingDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatal("successful native staging left installer bytes", err)
	}
}
