package windowssoftware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
)

type stageFixture struct {
	artifact enrollment.SoftwareArtifact
	root     string
	client   *http.Client
	content  []byte
	requests atomic.Int32
	handler  func(http.ResponseWriter, *http.Request)
}

func newStageFixture(t *testing.T) *stageFixture {
	t.Helper()
	f := &stageFixture{root: filepath.Join(t.TempDir(), "private"), content: bytes.Repeat([]byte("owned inert installer fixture\n"), 1024)}
	if err := keyfile.CreateDirectory(f.root); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != "GET" || r.URL.Path != "/fixture."+f.artifact.Format || r.URL.RawQuery != "token=private-source" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "identity" || r.TLS == nil || len(r.TLS.PeerCertificates) != 0 {
			t.Error("artifact download carried identity or changed exact target")
		}
		if f.handler != nil {
			f.handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(f.content)
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, transport := newArtifactClient(roots)
	t.Cleanup(transport.CloseIdleConnections)
	f.client = client
	hash := sha256.Sum256(f.content)
	f.artifact = enrollment.SoftwareArtifact{URL: server.URL + "/fixture.exe?token=private-source", SHA256: hex.EncodeToString(hash[:]), Format: "exe"}
	return f
}
func assertStageEmpty(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed staging left an owned candidate", len(entries), err)
	}
}

func TestSoftwareStagingChecksExactPrivateBytesBeforeAndAfterNativePolicy(t *testing.T) {
	f := newStageFixture(t)
	checks := 0
	stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, func(ctx context.Context, path, format string) error {
		checks++
		if format != "exe" || keyfile.CheckDirectory(filepath.Dir(path)) != nil {
			t.Error("signature check lacked private candidate")
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, f.content) {
			t.Error("signature check saw different bytes", err)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 15*time.Minute {
			t.Error("unbounded signature/download context")
		}
		return nil
	})
	if err != nil || stage == nil || checks != 1 || f.requests.Load() != 1 {
		t.Fatal("exact private staging failed", err)
	}
	if err = stage.Verify(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = stage.Close(); err != nil || stage.Path() != "" || stage.Verify(t.Context()) == nil {
		t.Fatal("closed candidate remained usable", err)
	}
	assertStageEmpty(t, f.root)
}

func TestSoftwareStagingRejectsDownloadChangesAndNeverReachesNativePolicy(t *testing.T) {
	for _, failure := range []string{"hash", "partial", "empty", "oversized", "encoded", "status", "redirect", "cancelled", "tls"} {
		t.Run(failure, func(t *testing.T) {
			f := newStageFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch failure {
			case "hash":
				f.artifact.SHA256 = strings.Repeat("0", 64)
			case "partial":
				f.handler = func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", "100")
					_, _ = w.Write([]byte("short"))
				}
			case "empty":
				f.handler = func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Length", "0") }
			case "oversized":
				f.handler = func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", strconv.Itoa(artifacts.MaxPackageSize+1))
					w.WriteHeader(http.StatusOK)
				}
			case "encoded":
				f.handler = func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write(f.content)
				}
			case "status":
				f.handler = func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusPartialContent)
					_, _ = w.Write(f.content)
				}
			case "redirect":
				f.handler = func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Location", "https://uncontacted.example.test/fixture.exe")
					w.WriteHeader(http.StatusFound)
				}
			case "cancelled":
				cancel()
			case "tls":
				var transport *http.Transport
				f.client, transport = newArtifactClient(nil)
				defer transport.CloseIdleConnections()
			}
			stage, err := stageArtifact(ctx, f.artifact, f.root, f.client, func(context.Context, string, string) error {
				t.Error("invalid download reached native policy")
				return nil
			})
			if stage != nil || !errors.Is(err, ErrArtifactDownload) {
				t.Fatal("invalid transfer accepted", err)
			}
			if strings.Contains(err.Error(), "private-source") {
				t.Fatal("source credential escaped in error")
			}
			assertStageEmpty(t, f.root)
		})
	}
}

func TestSoftwareStagingRetainsNativeDenialAndRejectsChangedFiles(t *testing.T) {
	f := newStageFixture(t)
	stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, func(context.Context, string, string) error { return errors.New("owned private native diagnostic") })
	if stage != nil || !errors.Is(err, ErrArtifactSignature) || strings.Contains(err.Error(), "diagnostic") {
		t.Fatal("native denial leaked or accepted", err)
	}
	assertStageEmpty(t, f.root)
	stage, err = stageArtifact(t.Context(), f.artifact, f.root, f.client, func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	err = os.WriteFile(stage.Path(), []byte("changed"), 0600)
	if runtime.GOOS == "windows" {
		if err == nil {
			t.Fatal("Windows staged descriptor allowed a writer")
		}
		if stage.Verify(t.Context()) != nil {
			t.Fatal("denied writer changed candidate")
		}
	} else if err != nil || stage.Verify(t.Context()) == nil {
		t.Fatal("portable byte recheck missed changed file", err)
	}
}

func TestSoftwareStagingRejectsPostSignatureMutationOrPreventsItNatively(t *testing.T) {
	f := newStageFixture(t)
	stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, func(_ context.Context, path, _ string) error {
		err := os.WriteFile(path, []byte("changed after native check"), 0600)
		if runtime.GOOS == "windows" && err == nil {
			t.Error("signature window allowed concurrent writer")
		}
		if runtime.GOOS != "windows" && err != nil {
			t.Error(err)
		}
		return nil
	})
	if runtime.GOOS == "windows" {
		if err != nil || stage == nil {
			t.Fatal("protected file was changed", err)
		}
		_ = stage.Close()
	} else if stage != nil || !errors.Is(err, ErrArtifactChanged) {
		t.Fatal("signature-time mutation was accepted", err)
	}
	assertStageEmpty(t, f.root)
}

func TestSoftwareArtifactTransportHasNoSharedCredentialsOrProxy(t *testing.T) {
	f := newStageFixture(t)
	var proxies atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxies.Add(1); w.WriteHeader(500) }))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	transport, ok := f.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || f.client.Jar != nil || len(transport.TLSClientConfig.Certificates) != 0 || transport.TLSClientConfig.GetClientCertificate != nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("artifact transport borrowed credentials or trust bypass")
	}
	stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, func(context.Context, string, string) error { return nil })
	if err != nil || stage == nil || proxies.Load() != 0 {
		t.Fatal("artifact request used environment proxy", err)
	}
	_ = stage.Close()
}
