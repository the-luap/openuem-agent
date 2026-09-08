package bootstrapinstall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
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

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
)

func TestMain(m *testing.M) {
	if handled, code := packagesignature.HandleHelper(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

type stagingFixture struct {
	verified *bootstrap.Verified
	client   *enrollment.HTTPClient
	root     string
	content  []byte
	body     atomic.Value
}

func newStagingFixture(t *testing.T, content []byte, agentBytes ...[]byte) *stagingFixture {
	t.Helper()
	f := &stagingFixture{content: content, root: filepath.Join(t.TempDir(), "staging")}
	if err := keyfile.CreateDirectory(f.root); err != nil {
		t.Fatal(err)
	}
	f.body.Store(content)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(f.body.Load().([]byte))
	}))
	t.Cleanup(server.Close)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	configPublic, configPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(configPrivate)
	platform, format := "windows", "exe"
	if runtime.GOOS == "darwin" {
		platform, format = "macos", "pkg"
	}
	now := time.Now().UTC()
	digest := sha256.Sum256(content)
	manifest := artifacts.Manifest{Schema: 1, Sequence: 42, Version: "0.12.0", PublishedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour), Artifacts: []artifacts.Artifact{{Platform: platform, Architecture: runtime.GOARCH, Format: format, Filename: "openuem-agent-0.12.0-" + platform + "-" + runtime.GOARCH + "." + format, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}}}
	if len(agentBytes) > 0 {
		digest := sha256.Sum256(agentBytes[0])
		manifest.Artifacts[0].AgentSize = int64(len(agentBytes[0]))
		manifest.Artifacts[0].AgentSHA256 = hex.EncodeToString(digest[:])
	}
	releaseData, err := artifacts.Sign(manifest, private, now)
	if err != nil {
		t.Fatal(err)
	}
	release, err := artifacts.Verify(releaseData, []ed25519.PublicKey{public}, now, artifacts.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	config := bootstrap.Config{Schema: 1, Origin: server.URL, Organization: "Isolated organization", Site: "Fixture site", TenantID: 3, SiteID: 4, Invitation: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)), Platform: platform, Architecture: runtime.GOARCH, IssuedAt: now, ExpiresAt: now.Add(time.Hour), ReleaseDigest: release.Digest(), ReleaseEnvelope: releaseData}
	data, err := bootstrap.Sign(config, configPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	f.verified, err = bootstrap.Verify(data, bootstrap.Trust{Origin: server.URL, Platform: platform, Architecture: runtime.GOARCH, BootstrapKeys: []ed25519.PublicKey{configPublic}, ReleaseKeys: []ed25519.PublicKey{public}}, now)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	f.client, err = enrollment.NewHTTPClient(server.URL, roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

func assertEmptyStaging(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("owned staging was not cleaned", err)
	}
}

func TestStagingVerifiesPrivateBytesBeforeAndAfterNativePolicyAndJoinsClose(t *testing.T) {
	f := newStagingFixture(t, bytes.Repeat([]byte("non-executable fixture"), 4096))
	calls := 0
	p, err := stagePackage(context.Background(), f.verified, f.client, f.root, artifacts.Checkpoint{}, func(ctx context.Context, path, format string) error {
		calls++
		file, err := keyfile.Open(path, int64(len(f.content)))
		if err != nil {
			return err
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil || !bytes.Equal(data, f.content) || format != f.verified.Artifact().Format {
			return errors.New("wrong staged fixture")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if calls != 1 || p.Path() == "" {
		t.Fatal("native verification did not run once")
	}
	if err := p.Verify(context.Background(), f.verified, f.verified.Checkpoint()); err != nil {
		t.Fatal(err)
	}
	newer := artifacts.Checkpoint{Sequence: 43, Digest: strings.Repeat("a", 64)}
	if err := p.Verify(context.Background(), f.verified, newer); !errors.Is(err, artifacts.ErrRollback) {
		t.Fatal("staged package reset durable checkpoint", err)
	}
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			if err := p.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if p.Path() != "" || p.Verify(context.Background(), f.verified, artifacts.Checkpoint{}) == nil {
		t.Fatal("closed staging remained usable")
	}
	assertEmptyStaging(t, f.root)
}

func TestStagingRejectsPartialDownloadsNativeFailureMutationAndCancellation(t *testing.T) {
	for _, kind := range []string{"partial", "native failure", "mutation", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := newStagingFixture(t, []byte("non-executable fixture"))
			if kind == "partial" {
				f.body.Store(f.content[:1])
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			p, err := stagePackage(ctx, f.verified, f.client, f.root, artifacts.Checkpoint{}, func(ctx context.Context, path, format string) error {
				calls++
				switch kind {
				case "native failure":
					return errors.New("private fixture diagnostic")
				case "mutation":
					file, err := os.OpenFile(path, os.O_WRONLY, 0)
					if err != nil {
						return err
					}
					_, err = file.WriteAt([]byte("X"), 0)
					file.Close()
					return err
				case "cancel":
					cancel()
					return ctx.Err()
				}
				return nil
			})
			if p != nil || err == nil {
				if p != nil {
					p.Close()
				}
				t.Fatal("unsafe staging succeeded")
			}
			if kind == "partial" && calls != 0 {
				t.Fatal("partial installer reached native verification")
			}
			if kind == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("caller cancellation was lost", err)
			}
			if strings.Contains(err.Error(), "private fixture diagnostic") {
				t.Fatal("native diagnostics escaped")
			}
			assertEmptyStaging(t, f.root)
		})
	}
}

func TestStagingRejectsChangedFilesAndPreservesUnexpectedReplacements(t *testing.T) {
	f := newStagingFixture(t, []byte("non-executable fixture"))
	p, err := stagePackage(context.Background(), f.verified, f.client, f.root, artifacts.Checkpoint{}, func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	file, err := os.OpenFile(p.Path(), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteAt([]byte("X"), 0)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); !errors.Is(err, ErrPackage) {
		t.Fatal("changed staged bytes were accepted", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	path := p.Path()
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Create(path, []byte("unexpected replacement")); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); !errors.Is(err, ErrPackage) {
		t.Fatal("replacement path was accepted", err)
	}
	if err := p.Close(); !errors.Is(err, ErrPackage) {
		t.Fatal("unexpected staging replacement was not reported", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "unexpected replacement" {
		t.Fatal("cleanup removed unrelated replacement", err)
	}
}

func TestPublicStagingRequiresNativePolicyAndActualPlatform(t *testing.T) {
	f := newStagingFixture(t, []byte("unsigned isolated fixture"))
	p, err := StagePackage(context.Background(), f.verified, f.client, f.root, artifacts.Checkpoint{})
	if p != nil || err == nil {
		if p != nil {
			p.Close()
		}
		t.Fatal("unsigned package or unsupported platform was accepted")
	}
	assertEmptyStaging(t, f.root)
	if runtime.GOOS == "windows" {
		content, err := os.ReadFile(filepath.Join("..", "packagesignature", "testdata", "ev-signed-file.exe"))
		if err != nil {
			t.Fatal(err)
		}
		signed := newStagingFixture(t, content)
		p, err := StagePackage(context.Background(), signed.verified, signed.client, signed.root, artifacts.Checkpoint{})
		if err != nil {
			t.Fatal("native signed staged fixture was rejected", err)
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		assertEmptyStaging(t, signed.root)
	}
}
