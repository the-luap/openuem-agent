package bootstrapinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestStoredExecutableBindingRequiresCanonicalHashAndRetainedBytes(t *testing.T) {
	content := []byte("installed executable binding fixture")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	path := filepath.Join(t.TempDir(), "agent")
	if err := keyfile.Create(path, content); err != nil {
		t.Fatal(err)
	}
	image, err := openAgentExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	ctx := context.Background()
	if err := image.VerifyStoredBinding(ctx, int64(len(content)), digest); err != nil {
		t.Fatal("completed binding could not be used without a live invitation", err)
	}
	for _, c := range []struct {
		size   int64
		digest string
	}{
		{0, digest}, {artifacts.MaxPackageSize + 1, digest}, {int64(len(content) + 1), digest},
		{int64(len(content)), ""}, {int64(len(content)), strings.ToUpper(digest)},
		{int64(len(content)), strings.Repeat("a", 64)},
	} {
		if err := image.VerifyStoredBinding(ctx, c.size, c.digest); !errors.Is(err, ErrPackage) {
			t.Fatal("invalid stored binding accepted", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := image.VerifyStoredBinding(canceled, int64(len(content)), digest); !errors.Is(err, context.Canceled) {
		t.Fatal("stored executable hashing ignored cancellation", err)
	}
	if runtime.GOOS != "windows" {
		// Preserve the path, length and timestamp: the content hash must still
		// catch a change. Windows denies writing while the image is retained.
		if err := os.WriteFile(path, []byte(strings.Repeat("x", len(content))), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, image.info.ModTime(), image.info.ModTime()); err != nil {
			t.Fatal(err)
		}
		if err := image.VerifyStoredBinding(ctx, int64(len(content)), digest); !errors.Is(err, ErrPackage) {
			t.Fatal("changed executable bytes retained the old identity binding", err)
		}
	}
	image.Close()
	if err := image.VerifyStoredBinding(ctx, int64(len(content)), digest); !errors.Is(err, ErrPackage) {
		t.Fatal("closed executable accepted a stored binding", err)
	}
}

func TestInstalledAgentRequiresSeparateReleaseBindingAndStableFileIdentity(t *testing.T) {
	content := []byte("non-executable installed-agent fixture")
	f := newStagingFixture(t, []byte("different installer fixture"), content)
	path := filepath.Join(f.root, "installed-agent")
	if err := keyfile.Create(path, content); err != nil {
		t.Fatal(err)
	}
	e, err := openAgentExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.verify(context.Background(), f.verified, artifacts.Checkpoint{}); err != nil {
		t.Fatal("installed bytes failed their separate binding", err)
	}
	preview := newStagingFixture(t, content)
	if err := e.verify(context.Background(), preview.verified, artifacts.Checkpoint{}); !errors.Is(err, artifacts.ErrAgentBinding) {
		t.Fatal("installer hash replaced missing executable binding", err)
	}
	wrong := newStagingFixture(t, []byte("package"), []byte("other executable"))
	if err := e.verify(context.Background(), wrong.verified, artifacts.Checkpoint{}); !errors.Is(err, artifacts.ErrAgentBinding) {
		t.Fatal("different agent binary accepted", err)
	}
	newer := artifacts.Checkpoint{Sequence: 43, Digest: strings.Repeat("a", 64)}
	if err := e.verify(context.Background(), f.verified, newer); !errors.Is(err, artifacts.ErrRollback) {
		t.Fatal("executable ignored durable checkpoint", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0666); err != nil {
			t.Fatal(err)
		}
		if err := e.verify(context.Background(), f.verified, artifacts.Checkpoint{}); !errors.Is(err, ErrPackage) {
			t.Fatal("publicly writable executable accepted", err)
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := keyfile.Create(path, content); err != nil {
			t.Fatal(err)
		}
		if err := e.verify(context.Background(), f.verified, artifacts.Checkpoint{}); !errors.Is(err, ErrPackage) {
			t.Fatal("different path identity accepted even with identical bytes", err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); !errors.Is(err, ErrPackage) {
		t.Fatal("closed executable remained usable", err)
	}
}

func TestRunningAgentOpensBeforeBootstrapAndChecksActualExecutableBytes(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		if _, err := OpenRunningAgent(); !errors.Is(err, ErrPackage) {
			t.Fatal("unsupported native platform accepted", err)
		}
		return
	}
	e, err := OpenRunningAgent()
	if err != nil {
		t.Fatal("could not bind the actual test executable", err)
	}
	defer e.Close()
	// The test binary is read as public fixture bytes, never copied into an
	// installer or executed as a payload. Its actual opened identity is retained.
	content, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	f := newStagingFixture(t, []byte("fixture installer"), content)
	if err := e.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); err != nil {
		t.Fatal("actual opened executable did not match the signed binding", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Verify(ctx, f.verified, artifacts.Checkpoint{}); !errors.Is(err, context.Canceled) {
		t.Fatal("executable ignored cancellation", err)
	}
}

func TestExecutableOpenRejectsAliasesAndUnsafePermissions(t *testing.T) {
	directory := t.TempDir()
	for _, path := range []string{"", "relative", directory, filepath.Join(directory, "missing")} {
		if e, err := openAgentExecutable(path); err == nil {
			e.Close()
			t.Fatal("unsafe executable path accepted")
		}
	}
	if runtime.GOOS != "windows" {
		path := filepath.Join(directory, "agent")
		if err := os.WriteFile(path, []byte("fixture"), 0644); err != nil {
			t.Fatal(err)
		}
		e, err := openAgentExecutable(path)
		if err != nil {
			t.Fatal("public read-only code permissions rejected", err)
		}
		e.Close()
		if err := os.Chmod(path, 0666); err != nil {
			t.Fatal(err)
		}
		if e, err := openAgentExecutable(path); err == nil {
			e.Close()
			t.Fatal("untrusted code write access accepted")
		}
		alias := filepath.Join(directory, "alias")
		if err := os.Symlink(path, alias); err != nil {
			t.Fatal(err)
		}
		if e, err := openAgentExecutable(alias); err == nil {
			e.Close()
			t.Fatal("executable symlink accepted")
		}
	}
}
