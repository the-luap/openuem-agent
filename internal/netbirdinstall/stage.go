// Package netbirdinstall prepares immutable Unix NetBird packages. Preparation
// never installs a package, starts a service, changes trust or admits a command.
package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment/keyfile"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
)

var (
	ErrDownload  = errors.New("the approved NetBird package could not be prepared")
	ErrChanged   = errors.New("the prepared NetBird package changed")
	ErrSignature = errors.New("the NetBird package native signature could not be verified")
)

// Prepared owns a private package and its original open descriptor. Its parent
// must remain protected against replacement throughout use. A prepared package
// is not authority to install: current authenticated approval, recipient,
// durable command admission and native package identity still require checks.
type Prepared struct {
	mu                      sync.Mutex
	directory, path, digest string
	descriptor              packageapi.Package
	directoryInfo, fileInfo os.FileInfo
	file                    *os.File
	closed                  bool
	closeErr                error
}

func (*Prepared) String() string               { return "[private prepared NetBird package]" }
func (p *Prepared) GoString() string           { return p.String() }
func (*Prepared) MarshalJSON() ([]byte, error) { return nil, ErrChanged }

// Stage requires the descriptor from an authenticated, current organization
// approval. The root must already be private beneath trusted ancestors. It uses
// an independent HTTPS transport without enrollment identity, environment proxy,
// cookies or redirects. On macOS native signature verification is mandatory.
// Preparation also requires matching native package metadata. Publisher trust
// on Linux and current approval/command authority remain independent requirements.
func Stage(ctx context.Context, descriptor packageapi.Package, tenant int64, root string) (*Prepared, error) {
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	if ctx == nil || !descriptor.MatchesTarget(tenant, platform, runtime.GOARCH) {
		return nil, ErrDownload
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	client, transport := newClient(nil)
	defer transport.CloseIdleConnections()
	prepared, err := stage(ctx, descriptor, root, client, packagesignature.Verify)
	if err != nil {
		return nil, err
	}
	if err = prepared.Inspect(ctx, descriptor); err != nil {
		_ = prepared.Close()
		return nil, err
	}
	return prepared, nil
}

func newClient(roots *x509.CertPool) (*http.Client, *http.Transport) {
	if roots != nil {
		roots = roots.Clone()
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 25 * time.Second, MaxResponseHeaderBytes: 32 << 10, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, DisableCompression: true, ForceAttemptHTTP2: true}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDownload }}, tr
}

func stage(ctx context.Context, descriptor packageapi.Package, root string, client *http.Client, native func(context.Context, string, string) error) (result *Prepared, resultErr error) {
	if ctx == nil || !descriptor.Valid() || client == nil || native == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || keyfile.CheckDirectory(root) != nil {
		return nil, ErrDownload
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	digest, err := descriptor.Digest()
	if err != nil {
		return nil, ErrDownload
	}
	p := &Prepared{directory: filepath.Join(root, "netbird-package-"+uuid.NewString()), digest: digest, descriptor: descriptor}
	if keyfile.CreateDirectory(p.directory) != nil {
		return nil, ErrDownload
	}
	p.directoryInfo, resultErr = os.Lstat(p.directory)
	if resultErr != nil {
		return nil, ErrDownload
	}
	p.path = filepath.Join(p.directory, "package."+descriptor.Format)
	defer func() {
		if resultErr != nil {
			_ = p.Close()
		}
	}()
	writer, err := keyfile.CreateFile(p.path)
	if err != nil {
		return nil, ErrDownload
	}
	p.fileInfo, err = writer.Stat()
	if err != nil {
		writer.Close()
		return nil, ErrDownload
	}
	err = download(ctx, client, descriptor, writer)
	if err == nil {
		err = writer.Sync()
	}
	closeErr := writer.Close()
	if err != nil || closeErr != nil {
		return nil, contextError(ctx, ErrDownload)
	}
	p.file, err = keyfile.Open(p.path, descriptor.Size)
	if err != nil {
		return nil, ErrChanged
	}
	if err = p.Verify(ctx, descriptor); err != nil {
		return nil, err
	}
	prefix := make([]byte, 8)
	n, err := p.file.ReadAt(prefix, 0)
	if err != nil && err != io.EOF {
		return nil, ErrDownload
	}
	valid := descriptor.Format == "deb" && n == 8 && string(prefix) == "!<arch>\n" || descriptor.Format == "rpm" && n >= 4 && string(prefix[:4]) == "\xed\xab\xee\xdb" || descriptor.Format == "pkg" && n >= 4 && string(prefix[:4]) == "xar!"
	if !valid {
		return nil, ErrDownload
	}
	if descriptor.Platform == "macos" {
		if err = native(ctx, p.path, descriptor.Format); err != nil {
			return nil, contextError(ctx, ErrSignature)
		}
	}
	if err = p.Verify(ctx, descriptor); err != nil {
		return nil, err
	}
	return p, nil
}

func download(ctx context.Context, client *http.Client, descriptor packageapi.Package, writer io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, descriptor.URL, nil)
	if err != nil {
		return ErrDownload
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "OpenUEM NetBird package preparation")
	response, err := client.Do(req)
	if err != nil {
		return contextError(ctx, ErrDownload)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" || response.ContentLength >= 0 && response.ContentLength != descriptor.Size {
		return ErrDownload
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(writer, hash), io.LimitReader(response.Body, descriptor.Size+1))
	if err != nil || n != descriptor.Size || hex.EncodeToString(hash.Sum(nil)) != descriptor.SHA256 {
		return contextError(ctx, ErrDownload)
	}
	return contextError(ctx, nil)
}

func contextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (p *Prepared) Path() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ""
	}
	return p.path
}

// Verify binds the same protected file and bytes to the exact descriptor again,
// including its approval, organization and source. It cannot re-authorize a
// withdrawn approval; the owner must hold and recheck that independent authority.
func (p *Prepared) Verify(ctx context.Context, descriptor packageapi.Package) error {
	if p == nil || ctx == nil {
		return ErrChanged
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.verifyLocked(ctx, descriptor)
}

func (p *Prepared) verifyLocked(ctx context.Context, descriptor packageapi.Package) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	digest, err := descriptor.Digest()
	if err != nil || p.closed || p.file == nil || p.fileInfo == nil || p.directoryInfo == nil || digest != p.digest || descriptor != p.descriptor || keyfile.CheckDirectory(p.directory) != nil {
		return ErrChanged
	}
	directory, err := os.Lstat(p.directory)
	if err != nil || !os.SameFile(directory, p.directoryInfo) {
		return ErrChanged
	}
	entry, err := os.Lstat(p.path)
	if err != nil || !entry.Mode().IsRegular() || !os.SameFile(entry, p.fileInfo) || entry.Size() != descriptor.Size {
		return ErrChanged
	}
	current, err := keyfile.Open(p.path, descriptor.Size)
	if err != nil {
		return ErrChanged
	}
	info, err := current.Stat()
	closeErr := current.Close()
	if err != nil || closeErr != nil || !os.SameFile(info, p.fileInfo) {
		return ErrChanged
	}
	hash := sha256.New()
	n, err := io.Copy(hash, contextReader{ctx: ctx, reader: io.NewSectionReader(p.file, 0, descriptor.Size+1)})
	if err != nil || n != descriptor.Size || hex.EncodeToString(hash.Sum(nil)) != descriptor.SHA256 {
		return contextError(ctx, ErrChanged)
	}
	return contextError(ctx, nil)
}

// Close removes only this preparation's original file/directory. A replaced
// path is left untouched. Repeated Close calls return the same cleanup outcome.
func (p *Prepared) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.closeErr
	}
	p.closed = true
	if p.file != nil {
		p.closeErr = p.file.Close()
		p.file = nil
	}
	directory, err := os.Lstat(p.directory)
	if err != nil || p.directoryInfo == nil || !directory.IsDir() || !os.SameFile(directory, p.directoryInfo) || keyfile.CheckDirectory(p.directory) != nil {
		p.closeErr = ErrChanged
		return p.closeErr
	}
	entry, err := os.Lstat(p.path)
	if err == nil {
		if p.fileInfo == nil || !entry.Mode().IsRegular() || !os.SameFile(entry, p.fileInfo) {
			p.closeErr = ErrChanged
			return p.closeErr
		}
		if os.Remove(p.path) != nil {
			p.closeErr = ErrChanged
			return p.closeErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		p.closeErr = ErrChanged
		return p.closeErr
	}
	if os.Remove(p.directory) != nil {
		p.closeErr = ErrChanged
	}
	return p.closeErr
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
