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
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/agent"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const fixtureServicePrefix = "OpenUEMActivationFixture-"

// Only the copied test binary supports this hook. The shipped command never
// accepts a service-name override. Both paths use the actual running image,
// native DPAPI and real SCM; the service constructs the actual individual agent
// but deliberately never starts inventory, broker or host-management work.
func TestMain(m *testing.M) {
	if len(os.Args) == 4 && (os.Args[1] == "activate" || os.Args[1] == "serve") && os.Args[2] == "-identity-directory" {
		directory := os.Args[3]
		name, err := readConfiguration(filepath.Join(directory, "fixture-service"))
		if err != nil || !strings.HasPrefix(string(name), fixtureServicePrefix) {
			os.Exit(2)
		}
		if _, err := uuid.Parse(strings.TrimPrefix(string(name), fixtureServicePrefix)); err != nil {
			os.Exit(2)
		}
		if os.Args[1] == "serve" {
			if svc.Run(string(name), &activationFixtureService{directory: directory}) != nil {
				os.Exit(1)
			}
			os.Exit(0)
		}
		deps := nativeDependencies()
		deps.prepare = func(ctx context.Context, path, directory string, identity *enrollmentstore.Identity) (installation, error) {
			return prepareWindows(ctx, path, directory, identity, string(name))
		}
		_, code := handle(context.Background(), os.Args[1:], os.Stdout, os.Stderr, func(ctx context.Context, options Options) (Result, error) {
			return run(ctx, options, deps)
		})
		os.Exit(code)
	}
	os.Exit(m.Run())
}

type activationFixtureService struct{ directory string }

func (s *activationFixtureService) Execute(_ []string, controls <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending, WaitHint: 30000}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return true, 2
	}
	if _, err := os.Stat(filepath.Join(s.directory, "fixture-fail-start")); err == nil {
		return true, 3
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime, err := agent.NewIndividual(ctx, s.directory)
	if err != nil {
		return true, 4
	}
	defer runtime.Stop()
	if runtime.Config.UUID != fixtureDeviceID || runtime.Config.TenantID != "3" || runtime.Config.SiteID != "4" || !runtime.Config.SFTPDisabled || !runtime.Config.RemoteAssistanceDisabled {
		return true, 5
	}
	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- status
	for control := range controls {
		switch control.Cmd {
		case svc.Interrogate:
			statuses <- status
		case svc.Stop, svc.Shutdown:
			statuses <- svc.Status{State: svc.StopPending, WaitHint: 30000}
			cancel()
			return false, 0
		}
	}
	return false, 0
}

type windowsActivationFixture struct {
	root, executable, directory, name string
	manager                           *mgr.Mgr
}

func writePrivateFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := privateDescriptor(false)
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
}

func newWindowsActivationFixture(t *testing.T, wrongBinding bool) *windowsActivationFixture {
	t.Helper()
	f := &windowsActivationFixture{root: filepath.Join(t.TempDir(), "Installed agent"), name: fixtureServicePrefix + uuid.NewString()}
	directory, err := ensurePrivateDirectory(f.root)
	if err != nil {
		t.Fatal(err)
	}
	directory.Close()
	f.executable, f.directory = filepath.Join(f.root, "agent.exe"), filepath.Join(f.root, "identity")
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	writePrivateFixture(t, f.executable, data)
	sum := sha256.Sum256(data)
	if wrongBinding {
		sum[0] ^= 0xff
	}
	bootstrap := enrollmentstore.Bootstrap{
		Invitation: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{29}, 32)), Platform: "windows", Architecture: runtime.GOARCH,
		DeviceName: "Native activation fixture", TenantID: 3, SiteID: 4, ReleaseSequence: 42, ReleaseDigest: strings.Repeat("a", 64),
		AgentSize: int64(len(data)), AgentSHA256: hex.EncodeToString(sum[:]),
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Isolated activation fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/enroll/desktop/"+bootstrap.Invitation+"/claim" {
			http.Error(w, "invalid", 400)
			return
		}
		var request enrollment.Request
		if json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&request) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		proof, err := enrollment.Validate(request)
		if err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: fixtureDeviceID}, URIs: []*url.URL{{Scheme: "urn", Opaque: "openuem:agent:" + fixtureDeviceID}}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, proof.CertificateKey, key)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(enrollment.Response{Version: 1, DeviceID: fixtureDeviceID, TenantID: 3, SiteID: 4, Endpoint: "wss://" + r.Host + "/agent-channel", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Authority: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})), ExpiresAt: leaf.NotAfter})
	}))
	t.Cleanup(server.Close)
	bootstrap.Origin = server.URL
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	store, err := enrollmentstore.Open(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identity, err := store.Enroll(context.Background(), bootstrap, roots)
	if err != nil {
		t.Fatal(err)
	}
	identity.Close()
	// Activation and service startup now have no live issuer to contact.
	server.Close()
	writePrivateFixture(t, filepath.Join(f.directory, "fixture-service"), []byte(f.name))
	f.manager, err = mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer f.manager.Disconnect()
		service, err := f.manager.OpenService(f.name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return
		}
		if err != nil {
			t.Error(err)
			return
		}
		defer service.Close()
		_, _ = service.Control(svc.Stop)
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			status, err := service.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err := service.Delete(); err != nil {
			t.Error("fixture service cleanup failed", err)
		}
	})
	return f
}

func (f *windowsActivationFixture) activate(t *testing.T) (Result, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, f.executable, "activate", "-identity-directory", f.directory)
	var output, diagnostics bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostics
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatal("fixture activation timed out", diagnostics.String())
	}
	var result Result
	if output.Len() > 0 {
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal("activation wrote non-public output", err)
		}
	}
	return result, diagnostics.Bytes(), err
}

func (f *windowsActivationFixture) protectedSnapshot(t *testing.T) map[string][32]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(f.directory, "*.dpapi"))
	if err != nil || len(paths) != 2 {
		t.Fatal("incomplete native identity", err)
	}
	result := make(map[string][32]byte)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[path] = sha256.Sum256(data)
	}
	return result
}

func TestNativeWindowsActivationAndRecoveryUseTheCompletedProtectedIdentity(t *testing.T) {
	for _, failedStart := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "start-failure-recovery"}[failedStart], func(t *testing.T) {
			f := newWindowsActivationFixture(t, false)
			before := f.protectedSnapshot(t)
			marker := filepath.Join(f.directory, "fixture-fail-start")
			if failedStart {
				writePrivateFixture(t, marker, []byte("isolated startup failure"))
			}
			result, diagnostics, err := f.activate(t)
			if !result.Registered || result.Running == failedStart || (err != nil) != failedStart || result.DeviceID != fixtureDeviceID || result.TenantID != 3 || result.SiteID != 4 {
				t.Fatalf("unexpected native activation result: %+v, %v, %s", result, err, diagnostics)
			}
			service, err := f.manager.OpenService(f.name)
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			config, err := service.Config()
			args := []string{f.executable, "serve", "-identity-directory", f.directory}
			for i := range args {
				args[i] = syscall.EscapeArg(args[i])
			}
			if err != nil || config.BinaryPathName != strings.Join(args, " ") || config.StartType != mgr.StartAutomatic || config.ServiceStartName != "LocalSystem" {
				t.Fatal("SCM registration changed account, startup or protected arguments", err)
			}
			if failedStart {
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(f.root, "config", "openuem.ini")
			data, err := readConfiguration(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := bytes.ReplaceAll(data, []byte("DefaultFrequency = 15"), []byte("DefaultFrequency = 60"))
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			again, diagnostics, err := f.activate(t)
			if err != nil || !again.Registered || !again.Running || again.DeviceID != result.DeviceID {
				t.Fatalf("retry failed: %+v %v %s", again, err, diagnostics)
			}
			actual, err := readConfiguration(path)
			if err != nil || !bytes.Equal(actual, changed) {
				t.Fatal("activation overwrote operational changes", err)
			}
			for path, sum := range f.protectedSnapshot(t) {
				if sum != before[path] {
					t.Fatal("activation replaced protected identity state")
				}
			}
			status, err := service.Query()
			if err != nil || status.State != svc.Running {
				t.Fatal("reported success without a running native service", err)
			}
		})
	}
}

func TestNativeWindowsActivationRejectsForeignServiceConfigurationAndBinary(t *testing.T) {
	for _, scenario := range []string{"foreign-service", "legacy-configuration", "wrong-executable-binding", "writable-installation", "public-configuration"} {
		t.Run(scenario, func(t *testing.T) {
			f := newWindowsActivationFixture(t, scenario == "wrong-executable-binding")
			before := f.protectedSnapshot(t)
			configPath := filepath.Join(f.root, "config", "openuem.ini")
			legacy := []byte("[Agent]\nUUID = old-device\n")
			if scenario == "foreign-service" {
				service, err := f.manager.CreateService(f.name, f.executable, mgr.Config{StartType: mgr.StartManual, DisplayName: f.name}, "foreign-arguments")
				if err != nil {
					t.Fatal(err)
				}
				service.Close()
			}
			if scenario == "legacy-configuration" || scenario == "public-configuration" {
				directory, err := ensurePrivateDirectory(filepath.Dir(configPath))
				if err != nil {
					t.Fatal(err)
				}
				directory.Close()
				writePrivateFixture(t, configPath, legacy)
			}
			if scenario == "writable-installation" {
				setFixtureDACL(t, f.root, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FW;;;WD)")
			}
			if scenario == "public-configuration" {
				if err := os.WriteFile(configPath, configuration(&enrollmentstore.Identity{Response: enrollment.Response{DeviceID: fixtureDeviceID}}), 0600); err != nil {
					t.Fatal(err)
				}
				setFixtureDACL(t, configPath, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)")
			}
			result, _, err := f.activate(t)
			if err == nil || result.Registered || result.Running {
				t.Fatal("unsafe installation was activated", result)
			}
			if _, err := os.Lstat(filepath.Join(f.root, "logs")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected preflight created log directory", err)
			}
			if scenario == "legacy-configuration" {
				data, err := os.ReadFile(configPath)
				if err != nil || !bytes.Equal(data, legacy) {
					t.Fatal("legacy configuration was replaced", err)
				}
			} else if scenario != "public-configuration" {
				if _, err := os.Lstat(filepath.Dir(configPath)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("rejected preflight created configuration", err)
				}
			}
			if scenario != "foreign-service" {
				service, err := f.manager.OpenService(f.name)
				if service != nil {
					service.Close()
					t.Fatal("rejected preflight registered service")
				}
				if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
					t.Fatal(err)
				}
			}
			for path, sum := range f.protectedSnapshot(t) {
				if sum != before[path] {
					t.Fatal("rejected activation altered identity")
				}
			}
		})
	}
}

func setFixtureDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(sd)
}

func TestNativeWindowsServiceIndependentlyRejectsAChangedExecutableBinding(t *testing.T) {
	f := newWindowsActivationFixture(t, true)
	store, err := enrollmentstore.Open(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identity, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	// Simulate an administrator registering the service without the activation
	// admission gate. The actual agent constructor must still reject its bytes.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	plan, err := prepareWindows(ctx, f.executable, f.directory, identity, f.name)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	if err := plan.PrepareConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := plan.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := plan.Start(ctx); !errors.Is(err, ErrStart) {
		t.Fatal("service accepted the wrong executable binding", err)
	}
	status, err := plan.service.Query()
	if err != nil || status.State != svc.Stopped || status.ServiceSpecificExitCode != 4 {
		t.Fatalf("service did not independently reject its protected identity: %+v %v", status, err)
	}
}
