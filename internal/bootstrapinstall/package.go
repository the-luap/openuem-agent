// Package bootstrapinstall joins verified bootstrap data to private native
// installation staging. It never treats download completion as installation.
package bootstrapinstall

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
)

var ErrPackage = errors.New("the approved installer could not be prepared securely")

// Package owns one private staged installer and its read-only descriptor. Close
// removes only this staging instance. It contains no invitation or endpoint key.
// Do not retain Path after Close; call Verify immediately before its eventual use.
type Package struct {
	mu                      sync.Mutex
	directory, path, digest string
	artifact                artifacts.Artifact
	file                    *os.File
	info                    os.FileInfo
	closed                  bool
}

// StagePackage requires independently verified configuration, the authorized
// HTTPS client and the latest protected release checkpoint. The staging root must
// already be private and beneath trusted ancestors. It downloads, syncs, hashes,
// checks native signatures and hashes the same open file again before returning.
// It does not claim an identity, install software or persist service configuration.
func StagePackage(ctx context.Context, verified *bootstrap.Verified, client *enrollment.HTTPClient, root string, checkpoint artifacts.Checkpoint) (*Package, error) {
	if verified == nil {
		return nil, ErrPackage
	}
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	config := verified.Config()
	if (platform != "windows" && platform != "macos") || config.Platform != platform || config.Architecture != runtime.GOARCH {
		return nil, bootstrap.ErrTarget
	}
	return stagePackage(ctx, verified, client, root, checkpoint, packagesignature.Verify)
}

func stagePackage(ctx context.Context, verified *bootstrap.Verified, client *enrollment.HTTPClient, root string, checkpoint artifacts.Checkpoint, checkNative func(context.Context, string, string) error) (result *Package, resultErr error) {
	if ctx == nil || verified == nil || client == nil || checkNative == nil {
		return nil, ErrPackage
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := verified.ValidAt(time.Now(), checkpoint); err != nil {
		return nil, err
	}
	if client.Origin() != verified.Config().Origin {
		return nil, bootstrap.ErrTarget
	}
	if filepath.Clean(root) != root || keyfile.CheckDirectory(root) != nil {
		return nil, ErrPackage
	}
	artifact := verified.Artifact()
	stage := &Package{directory: filepath.Join(root, "package-"+uuid.NewString()), digest: verified.Checkpoint().Digest, artifact: artifact}
	if err := keyfile.CreateDirectory(stage.directory); err != nil {
		return nil, ErrPackage
	}
	stage.path = filepath.Join(stage.directory, artifact.Filename)
	defer func() {
		if resultErr != nil {
			stage.Close()
		}
	}()
	writer, err := keyfile.CreateFile(stage.path)
	if err != nil {
		return nil, ErrPackage
	}
	stage.info, err = writer.Stat()
	if err != nil {
		writer.Close()
		return nil, ErrPackage
	}
	// The write handle closes before native verification; Windows WinTrust
	// deliberately excludes concurrent write/delete access to the candidate.
	err = verified.DownloadPackage(ctx, client, writer)
	if err == nil {
		err = writer.Sync()
	}
	closeErr := writer.Close()
	if err != nil || closeErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrPackage
	}
	stage.file, err = keyfile.Open(stage.path, artifact.Size)
	if err != nil {
		return nil, ErrPackage
	}
	if err = stage.Verify(ctx, verified, checkpoint); err != nil {
		return nil, err
	}
	if err = checkNative(ctx, stage.path, artifact.Format); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrPackage
	}
	if err = stage.Verify(ctx, verified, checkpoint); err != nil {
		return nil, err
	}
	return stage, nil
}

// Path is valid only while the package is open. It is not an authorization token.
func (p *Package) Path() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ""
	}
	return p.path
}

// Verify rechecks exact release/target/checkpoint/lifetime, private path identity
// and bytes through the owned descriptor. A newer checkpoint or changed file
// invalidates this package. Callers keep the verified path protected until use.
func (p *Package) Verify(ctx context.Context, verified *bootstrap.Verified, checkpoint artifacts.Checkpoint) error {
	if p == nil || ctx == nil || verified == nil {
		return ErrPackage
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.file == nil || p.info == nil {
		return ErrPackage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verified.ValidAt(time.Now(), checkpoint); err != nil {
		return err
	}
	if verified.Checkpoint().Digest != p.digest || verified.Artifact() != p.artifact || keyfile.CheckDirectory(p.directory) != nil {
		return ErrPackage
	}
	entry, err := os.Lstat(p.path)
	if err != nil || !entry.Mode().IsRegular() || !os.SameFile(p.info, entry) {
		return ErrPackage
	}
	current, err := keyfile.Open(p.path, p.artifact.Size)
	if err != nil {
		return ErrPackage
	}
	info, err := current.Stat()
	current.Close()
	if err != nil || !os.SameFile(p.info, info) {
		return ErrPackage
	}
	if err := verified.VerifyPackage(contextReader{ctx: ctx, reader: io.NewSectionReader(p.file, 0, p.artifact.Size+1)}); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrPackage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return verified.ValidAt(time.Now(), checkpoint)
}

func (p *Package) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var failed bool
	if p.file != nil {
		failed = p.file.Close() != nil
		p.file = nil
	}
	if p.info != nil {
		entry, err := os.Lstat(p.path)
		if err == nil && os.SameFile(p.info, entry) {
			failed = os.Remove(p.path) != nil || failed
		} else if !errors.Is(err, os.ErrNotExist) {
			failed = true
		}
	}
	// Never recursively remove staging: an unexpected replacement is retained
	// for investigation instead of deleting an unrelated file or directory.
	if p.directory != "" {
		if err := os.Remove(p.directory); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = true
		}
	}
	if failed {
		return ErrPackage
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}
