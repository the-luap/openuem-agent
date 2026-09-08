package bootstrapinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
)

// Executable owns the installed agent descriptor opened at bootstrap startup.
// Its path and ancestors must belong to the trusted installer. This is release
// byte verification, not remote attestation of the process or operating system.
type Executable struct {
	mu   sync.Mutex
	path string
	file *os.File
	info os.FileInfo
}

// OpenRunningAgent must run before bootstrap network requests. It binds the
// current executable path to a read-only file with trusted ownership and no
// untrusted write access. Windows also denies write/delete sharing while open.
// The caller retains it through enrollment and closes it after dependent work.
func OpenRunningAgent() (*Executable, error) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		return nil, ErrPackage
	}
	path, err := os.Executable()
	if err != nil {
		return nil, ErrPackage
	}
	return openAgentExecutable(path)
}

func openAgentExecutable(path string) (*Executable, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrPackage
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrPackage
	}
	file, err := openCodeFile(path)
	if err != nil {
		return nil, ErrPackage
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Size() <= 0 || info.Size() > artifacts.MaxPackageSize || codeFileProtected(file, info) != nil {
		file.Close()
		return nil, ErrPackage
	}
	return &Executable{path: path, file: file, info: info}, nil
}

// Verify requires the current native target and signed executable size/hash. It
// checks the same opened image, current path identity, ownership, modification
// metadata and release lifetime/checkpoint before and after reading. It never
// treats a package hash or version label as an installed-executable hash.
func (e *Executable) Verify(ctx context.Context, verified *bootstrap.Verified, checkpoint artifacts.Checkpoint) error {
	if e == nil || ctx == nil || verified == nil {
		return ErrPackage
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil || e.info == nil {
		return ErrPackage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	config := verified.Config()
	if (platform != "windows" && platform != "macos") || config.Platform != platform || config.Architecture != runtime.GOARCH {
		return bootstrap.ErrTarget
	}
	return e.verify(ctx, verified, checkpoint)
}

func (e *Executable) verify(ctx context.Context, verified *bootstrap.Verified, checkpoint artifacts.Checkpoint) error {
	if err := verified.ValidAt(time.Now(), checkpoint); err != nil {
		return err
	}
	if !e.unchanged() {
		return ErrPackage
	}
	if err := verified.VerifyAgent(contextReader{ctx: ctx, reader: io.NewSectionReader(e.file, 0, artifacts.MaxPackageSize+1)}); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if !e.unchanged() {
		return ErrPackage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return verified.ValidAt(time.Now(), checkpoint)
}

func (e *Executable) unchanged() bool {
	entry, err := os.Lstat(e.path)
	if err != nil || !entry.Mode().IsRegular() || !os.SameFile(e.info, entry) {
		return false
	}
	current, err := e.file.Stat()
	return err == nil && os.SameFile(e.info, current) && current.Size() == e.info.Size() && current.ModTime().Equal(e.info.ModTime()) && codeFileProtected(e.file, current) == nil
}

// InstalledPath returns the retained executable's path only while its local
// file identity and permissions remain unchanged. It does not verify a release
// signature/hash; enrollment must independently perform Verify before admitting
// an identity. Service activation uses this local check after loading that state.
func (e *Executable) InstalledPath() (string, error) {
	if e == nil {
		return "", ErrPackage
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil || e.info == nil || !e.unchanged() {
		return "", ErrPackage
	}
	return e.path, nil
}

// VerifyStoredBinding verifies the executable admitted during completed native
// enrollment, after its invitation/release envelope may have expired. The size
// and digest must come from protected identity state, never a command argument.
func (e *Executable) VerifyStoredBinding(ctx context.Context, size int64, digest string) error {
	if e == nil || ctx == nil || size <= 0 || size > artifacts.MaxPackageSize {
		return ErrPackage
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != digest {
		return ErrPackage
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.file == nil || e.info == nil || e.info.Size() != size || !e.unchanged() {
		return ErrPackage
	}
	hash := sha256.New()
	count, err := io.Copy(hash, contextReader{ctx: ctx, reader: io.NewSectionReader(e.file, 0, size+1)})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || count != size || hex.EncodeToString(hash.Sum(nil)) != digest || !e.unchanged() {
		return ErrPackage
	}
	return nil
}

func (e *Executable) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil {
		return nil
	}
	err := e.file.Close()
	e.file = nil
	if err != nil {
		return ErrPackage
	}
	return nil
}
