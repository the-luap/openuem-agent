package netbirdinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
	"github.com/stretchr/testify/require"
)

func inertPackage(format string) []byte {
	prefix := map[string]string{"deb": "!<arch>\n", "rpm": "\xed\xab\xee\xdb0000", "pkg": "xar!0000"}[format]
	return []byte(prefix + "Owned inert package preparation fixture; no executable payload.")
}
func packageFixture(t *testing.T, format string, handler func(http.ResponseWriter, *http.Request)) (packageapi.Package, *http.Client, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix package preparation fixture")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, tr := newClient(roots)
	t.Cleanup(tr.CloseIdleConnections)
	data := inertPackage(format)
	hash := sha256.Sum256(data)
	p := packageapi.Package{Schema: packageapi.Schema, ApprovalID: "10000000-0000-4000-8000-000000000001", TenantID: 1, Platform: "linux", Architecture: "amd64", Format: format, PackageID: "netbird", Version: "0.77.1-1", URL: server.URL + "/netbird." + format + "?source=owned-private-coordinate", Size: int64(len(data)), SHA256: hex.EncodeToString(hash[:])}
	if format == "pkg" {
		p.Platform = "macos"
		p.PackageID = "io.netbird.client"
	}
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0700))
	return p, client, root
}
func noNative(context.Context, string, string) error { return nil }

func TestPreparationOwnsExactBytesAndSource(t *testing.T) {
	for _, format := range []string{"deb", "rpm", "pkg"} {
		t.Run(format, func(t *testing.T) {
			var calls atomic.Int32
			p, client, root := packageFixture(t, format, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.Equal(t, "GET", r.Method)
				require.Equal(t, "/netbird."+format, r.URL.Path)
				require.Equal(t, "owned-private-coordinate", r.URL.Query().Get("source"))
				require.Empty(t, r.Header.Get("Authorization"))
				require.Empty(t, r.Header.Get("Cookie"))
				require.Nil(t, r.TLS.PeerCertificates)
				require.Equal(t, "identity", r.Header.Get("Accept-Encoding"))
				_, _ = w.Write(inertPackage(format))
			})
			nativeCalls := 0
			prepared, err := stage(t.Context(), p, root, client, func(ctx context.Context, path, kind string) error {
				nativeCalls++
				require.Equal(t, "pkg", kind)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, inertPackage(format), data)
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, int32(1), calls.Load())
			require.Equal(t, map[bool]int{true: 1, false: 0}[format == "pkg"], nativeCalls)
			path := prepared.Path()
			require.Equal(t, "package."+format, filepath.Base(path))
			require.NoError(t, prepared.Verify(t.Context(), p))
			for _, change := range []func(*packageapi.Package){func(d *packageapi.Package) { d.ApprovalID = "20000000-0000-4000-8000-000000000002" }, func(d *packageapi.Package) { d.TenantID = 2 }, func(d *packageapi.Package) { d.URL += "-changed" }, func(d *packageapi.Package) { d.Version = "0.77.2" }} {
				other := p
				change(&other)
				require.ErrorIs(t, prepared.Verify(t.Context(), other), ErrChanged)
			}
			require.NotContains(t, fmt.Sprintf("%v %#v", prepared, prepared), "owned-private-coordinate")
			_, err = json.Marshal(prepared)
			require.Error(t, err)
			require.NoError(t, prepared.Close())
			require.NoError(t, prepared.Close())
			require.Empty(t, prepared.Path())
			require.ErrorIs(t, prepared.Verify(t.Context(), p), ErrChanged)
			_, err = os.Stat(path)
			require.True(t, errors.Is(err, os.ErrNotExist))
			entries, err := os.ReadDir(root)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}

func TestPreparationRejectsDownloadAndNativeFailures(t *testing.T) {
	for _, failure := range []string{"status", "redirect", "compressed", "short", "long", "chunked-long", "digest", "container", "signature", "signature-changed", "tls"} {
		t.Run(failure, func(t *testing.T) {
			format := "deb"
			if strings.HasPrefix(failure, "signature") {
				format = "pkg"
			}
			var calls atomic.Int32
			p, client, root := packageFixture(t, format, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				data := inertPackage(format)
				switch failure {
				case "status":
					w.WriteHeader(500)
					_, _ = w.Write([]byte("private provider error"))
					return
				case "redirect":
					w.Header().Set("Location", "/netbird."+format)
					w.WriteHeader(302)
					return
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
				case "short":
					data = data[:len(data)-1]
				case "long":
					data = append(data, 'x')
				case "chunked-long":
					w.(http.Flusher).Flush()
					data = append(data, 'x')
				case "digest":
					data[len(data)-1] = 'x'
				case "container":
					data = bytes.Repeat([]byte("x"), len(data))
				}
				_, _ = w.Write(data)
			})
			if failure == "container" {
				hash := sha256.Sum256(bytes.Repeat([]byte("x"), int(p.Size)))
				p.SHA256 = hex.EncodeToString(hash[:])
			}
			if failure == "tls" {
				var tr *http.Transport
				client, tr = newClient(nil)
				defer tr.CloseIdleConnections()
			}
			prepared, err := stage(t.Context(), p, root, client, func(ctx context.Context, path, kind string) error {
				if failure == "signature" {
					return errors.New("private native output")
				}
				if failure == "signature-changed" {
					return os.WriteFile(path, bytes.Repeat([]byte("x"), int(p.Size)), 0600)
				}
				return nil
			})
			require.Error(t, err)
			require.Nil(t, prepared)
			require.NotContains(t, err.Error(), "private")
			require.LessOrEqual(t, calls.Load(), int32(1))
			entries, err := os.ReadDir(root)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}

func TestPreparationCancellationAndNoEnvironmentTransport(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	p, client, root := packageFixture(t, "deb", func(w http.ResponseWriter, r *http.Request) { w.(http.Flusher).Flush(); <-r.Context().Done() })
	transport := client.Transport.(*http.Transport)
	require.Nil(t, transport.Proxy)
	require.Nil(t, transport.TLSClientConfig.Certificates)
	require.Nil(t, client.Jar)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	prepared, err := stage(ctx, p, root, client, noNative)
	require.Nil(t, prepared)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Empty(t, entries)
	cancelled, stop := context.WithCancel(t.Context())
	stop()
	_, err = stage(cancelled, p, root, client, noNative)
	require.ErrorIs(t, err, context.Canceled)
}

func TestPreparationRejectsTargetAndUnsafeRootBeforeDownload(t *testing.T) {
	var calls atomic.Int32
	p, client, root := packageFixture(t, "deb", func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write(inertPackage("deb")) })
	_, err := Stage(t.Context(), p, 2, root)
	require.ErrorIs(t, err, ErrDownload)
	require.Zero(t, calls.Load())
	oversized := p
	oversized.URL += strings.Repeat("&", 1800)
	require.True(t, oversized.Valid())
	_, err = packageapi.Encode(oversized)
	require.Error(t, err, "escaped source exceeds the bounded wire envelope")
	_, err = stage(t.Context(), oversized, root, client, noNative)
	require.ErrorIs(t, err, ErrDownload)
	require.Zero(t, calls.Load())
	for _, unsafe := range []string{root + "/..", "relative"} {
		_, err = stage(t.Context(), p, unsafe, client, noNative)
		require.ErrorIs(t, err, ErrDownload)
	}
	require.NoError(t, os.Chmod(root, 0755))
	_, err = stage(t.Context(), p, root, client, noNative)
	require.ErrorIs(t, err, ErrDownload)
	require.NoError(t, os.Chmod(root, 0700))
	link := filepath.Join(t.TempDir(), "alias")
	require.NoError(t, os.Symlink(root, link))
	_, err = stage(t.Context(), p, link, client, noNative)
	require.ErrorIs(t, err, ErrDownload)
	require.Zero(t, calls.Load())
}

func TestPreparationDetectsReplacementAndPreservesForeignPaths(t *testing.T) {
	for _, change := range []string{"bytes", "file", "symlink", "directory", "permissions"} {
		t.Run(change, func(t *testing.T) {
			p, client, root := packageFixture(t, "deb", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(inertPackage("deb")) })
			prepared, err := stage(t.Context(), p, root, client, noNative)
			require.NoError(t, err)
			path := prepared.Path()
			directory := filepath.Dir(path)
			switch change {
			case "bytes":
				require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte("x"), int(p.Size)), 0600))
			case "file":
				require.NoError(t, os.Rename(path, path+".old"))
				require.NoError(t, os.WriteFile(path, inertPackage("deb"), 0600))
			case "symlink":
				require.NoError(t, os.Rename(path, path+".old"))
				require.NoError(t, os.Symlink(path+".old", path))
			case "directory":
				require.NoError(t, os.Rename(directory, directory+".old"))
				require.NoError(t, os.Mkdir(directory, 0700))
				require.NoError(t, os.WriteFile(path, inertPackage("deb"), 0600))
			case "permissions":
				require.NoError(t, os.Chmod(path, 0644))
			}
			require.ErrorIs(t, prepared.Verify(t.Context(), p), ErrChanged)
			err = prepared.Close()
			if change == "file" || change == "symlink" || change == "directory" {
				require.ErrorIs(t, err, ErrChanged)
				_, statErr := os.Lstat(path)
				require.NoError(t, statErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPreparationConcurrentCloseAndVerification(t *testing.T) {
	p, client, root := packageFixture(t, "deb", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(inertPackage("deb")) })
	prepared, err := stage(t.Context(), p, root, client, noNative)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = prepared.Path()
			_ = prepared.Verify(t.Context(), p)
			_ = prepared.Close()
		}()
	}
	wg.Wait()
	require.NoError(t, prepared.Close())
	require.Empty(t, prepared.Path())
}

func TestMacPreparationRequiresRealNativeTrust(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native macOS trust fixture")
	}
	p, client, root := packageFixture(t, "pkg", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(inertPackage("pkg")) })
	prepared, err := stage(t.Context(), p, root, client, packagesignature.Verify)
	require.Nil(t, prepared)
	require.ErrorIs(t, err, ErrSignature)
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Empty(t, entries)
}
