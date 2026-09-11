package windowssoftware

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
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
)

var (
	ErrArtifactDownload  = errors.New("the approved Windows installer could not be downloaded")
	ErrArtifactSignature = errors.New("the approved Windows installer signature could not be verified")
	ErrArtifactChanged   = errors.New("the approved Windows installer file changed")
)

// StagedArtifact owns a private installer and a retained read-only descriptor.
// Windows excludes concurrent write/delete sharing until Close. This object is
// not authorization to execute: the caller still holds the signed task, durable
// attempt and installation service lease, and rechecks them immediately before use.
type StagedArtifact struct {
	mu                      sync.Mutex
	directory, path, digest string
	file                    *os.File
	fileInfo, directoryInfo os.FileInfo
	size                    int64
	closed                  bool
}

func (*StagedArtifact) String() string               { return "[private staged Windows installer]" }
func (s *StagedArtifact) GoString() string           { return s.String() }
func (*StagedArtifact) MarshalJSON() ([]byte, error) { return nil, ErrArtifactChanged }

// Stage requires an already authenticated executable plan and a protected root
// beneath administrator-controlled ancestors. Third-party downloads never use
// the enrollment transport, identity certificate, cookies, environment proxy or
// redirects. This method neither executes the candidate nor admits a retry.
func Stage(ctx context.Context, plan enrollment.SoftwarePlan, root string) (*StagedArtifact, error) {
	if runtime.GOOS != "windows" || !plan.Valid() || !plan.Artifact.Valid() {
		return nil, ErrArtifactDownload
	}
	client, transport := newArtifactClient(nil)
	defer transport.CloseIdleConnections()
	return stageArtifact(ctx, plan.Artifact, root, client, packagesignature.Verify)
}

func newArtifactClient(roots *x509.CertPool) (*http.Client, *http.Transport) {
	if roots != nil {
		roots = roots.Clone()
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 25 * time.Second, MaxResponseHeaderBytes: 32 << 10, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, DisableCompression: true, ForceAttemptHTTP2: true}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrArtifactDownload }}, transport
}

func stageArtifact(ctx context.Context, artifact enrollment.SoftwareArtifact, root string, client *http.Client, verify func(context.Context, string, string) error) (result *StagedArtifact, resultErr error) {
	if ctx == nil || ctx.Err() != nil || !artifact.Valid() || client == nil || verify == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || keyfile.CheckDirectory(root) != nil {
		return nil, ErrArtifactDownload
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	stage := &StagedArtifact{directory: filepath.Join(root, "installer-stage-"+uuid.NewString()), digest: artifact.SHA256}
	if keyfile.CreateDirectory(stage.directory) != nil {
		return nil, ErrArtifactDownload
	}
	stage.directoryInfo, resultErr = os.Lstat(stage.directory)
	if resultErr != nil {
		return nil, ErrArtifactDownload
	}
	stage.path = filepath.Join(stage.directory, "installer."+artifact.Format)
	defer func() {
		if resultErr != nil {
			_ = stage.Close()
		}
	}()
	writer, err := keyfile.CreateFile(stage.path)
	if err != nil {
		return nil, ErrArtifactDownload
	}
	stage.fileInfo, err = writer.Stat()
	if err != nil {
		writer.Close()
		return nil, ErrArtifactDownload
	}
	err = downloadArtifact(ctx, client, artifact, writer)
	if err == nil {
		err = writer.Sync()
	}
	info, statErr := writer.Stat()
	closeErr := writer.Close()
	if err != nil || statErr != nil || closeErr != nil || info.Size() <= 0 || info.Size() > artifacts.MaxPackageSize {
		return nil, ErrArtifactDownload
	}
	stage.size = info.Size()
	stage.file, err = openStagedArtifact(stage.path, stage.size)
	if err != nil {
		return nil, ErrArtifactChanged
	}
	if stage.Verify(ctx) != nil {
		return nil, ErrArtifactChanged
	}
	if verify(ctx, stage.path, artifact.Format) != nil {
		return nil, ErrArtifactSignature
	}
	if stage.Verify(ctx) != nil {
		return nil, ErrArtifactChanged
	}
	return stage, nil
}

func downloadArtifact(ctx context.Context, client *http.Client, artifact enrollment.SoftwareArtifact, writer io.Writer) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return ErrArtifactDownload
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "OpenUEM Windows software")
	response, err := client.Do(request)
	if err != nil {
		return ErrArtifactDownload
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" || response.ContentLength == 0 || response.ContentLength > artifacts.MaxPackageSize {
		return ErrArtifactDownload
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(writer, hash), io.LimitReader(response.Body, artifacts.MaxPackageSize+1))
	if err != nil || n <= 0 || n > artifacts.MaxPackageSize || response.ContentLength >= 0 && n != response.ContentLength || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 || ctx.Err() != nil {
		return ErrArtifactDownload
	}
	return nil
}

func (s *StagedArtifact) Path() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ""
	}
	return s.path
}
func (s *StagedArtifact) Verify(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrArtifactChanged
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.file == nil || s.fileInfo == nil || s.directoryInfo == nil || ctx.Err() != nil || keyfile.CheckDirectory(s.directory) != nil {
		return ErrArtifactChanged
	}
	directory, err := os.Lstat(s.directory)
	if err != nil || !os.SameFile(directory, s.directoryInfo) {
		return ErrArtifactChanged
	}
	entry, err := os.Lstat(s.path)
	if err != nil || !entry.Mode().IsRegular() || !os.SameFile(entry, s.fileInfo) || entry.Size() != s.size {
		return ErrArtifactChanged
	}
	current, err := keyfile.Open(s.path, s.size)
	if err != nil {
		return ErrArtifactChanged
	}
	info, err := current.Stat()
	closeErr := current.Close()
	if err != nil || closeErr != nil || !os.SameFile(info, s.fileInfo) {
		return ErrArtifactChanged
	}
	hash := sha256.New()
	n, err := io.Copy(hash, stagingContextReader{ctx: ctx, reader: io.NewSectionReader(s.file, 0, s.size+1)})
	if err != nil || n != s.size || hex.EncodeToString(hash.Sum(nil)) != s.digest || ctx.Err() != nil {
		return ErrArtifactChanged
	}
	return nil
}
func (s *StagedArtifact) Close() error {
	return s.close(os.Remove)
}

// The removal seam lets owned native fixtures record redacted OS failures;
// production always uses os.Remove and returns only ErrArtifactChanged.
func (s *StagedArtifact) close(remove func(string) error) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	failed := false
	if s.file != nil {
		failed = s.file.Close() != nil
		s.file = nil
	}
	if s.fileInfo != nil {
		entry, err := os.Lstat(s.path)
		if err == nil && os.SameFile(entry, s.fileInfo) {
			failed = remove(s.path) != nil || failed
		} else if !errors.Is(err, os.ErrNotExist) {
			failed = true
		}
	}
	if s.directoryInfo != nil {
		entry, err := os.Lstat(s.directory)
		if err == nil && os.SameFile(entry, s.directoryInfo) {
			failed = remove(s.directory) != nil || failed
		} else if !errors.Is(err, os.ErrNotExist) {
			failed = true
		}
	}
	if failed {
		return ErrArtifactChanged
	}
	return nil
}

type stagingContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r stagingContextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}
