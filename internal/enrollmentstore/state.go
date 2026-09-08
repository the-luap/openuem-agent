package enrollmentstore

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/open-uem/nats/enrollment"
)

var (
	ErrPending  = errors.New("individual enrollment is pending; resume with the original bootstrap")
	ErrConflict = errors.New("existing individual enrollment belongs to a different bootstrap")
)

// Bootstrap must come from an independently authorized installation workflow.
// Validation here checks syntax and persisted retry binding, not release trust.
// In particular, a downloaded manifest cannot authorize its own signing key or
// server origin. ReleaseDigest identifies the separately verified release.
type Bootstrap struct {
	Origin        string `json:"origin"`
	Invitation    string `json:"invitation"`
	Platform      string `json:"platform"`
	Architecture  string `json:"architecture"`
	DeviceName    string `json:"device_name"`
	ReleaseDigest string `json:"release_digest"`
}

func (Bootstrap) String() string     { return "[individual enrollment bootstrap]" }
func (b Bootstrap) GoString() string { return b.String() }

func (b Bootstrap) valid() bool {
	digest, err := hex.DecodeString(b.ReleaseDigest)
	return enrollment.ValidOrigin(b.Origin) && enrollment.ValidToken(b.Invitation) &&
		(b.Platform == "windows" || b.Platform == "macos") &&
		(b.Architecture == "amd64" || b.Architecture == "arm64") &&
		len(b.DeviceName) <= 255 && utf8.ValidString(b.DeviceName) && !strings.ContainsAny(b.DeviceName, "\x00\r\n") &&
		err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == b.ReleaseDigest
}

// Identity owns its decoded keys. Stop their users before Close; they must not be
// shared with another Identity or serialized into configuration, logs or HTTP.
// Each successful Load/Enroll returns independent key material.
type Identity struct {
	Keys          *enrollment.Keys
	Response      enrollment.Response
	Origin        string
	ReleaseDigest string
	Platform      string
	Architecture  string
}

func (Identity) String() string               { return "[protected individual agent identity]" }
func (i Identity) GoString() string           { return i.String() }
func (Identity) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

func (i *Identity) Close() error {
	if i != nil {
		releaseKeys(i.Keys)
		i.Keys = nil
	}
	return nil
}

func releaseKeys(keys *enrollment.Keys) {
	if keys == nil {
		return
	}
	if keys.Broker != nil {
		keys.Broker.Wipe()
		keys.Broker = nil
	}
	// Go's RSA implementation can retain private precomputation internally. Drop
	// references; do not promise erasure of every runtime/compiler-managed copy.
	keys.Certificate = nil
}

// Store owns a native backend. Close waits for active operations; callers must
// cancel enrollment contexts before shutdown if they need to interrupt HTTP.
type Store struct {
	mu      sync.RWMutex
	backend NativeBackend
}

func Open(directory string) (*Store, error) {
	b, err := OpenNative(directory)
	if err != nil {
		return nil, err
	}
	return &Store{backend: b}, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backend == nil {
		return nil
	}
	err := s.backend.Close()
	s.backend = nil
	return err
}

// Load distinguishes an empty installation from a recoverable pending claim.
// Missing/corrupt pieces of an existing identity never become an empty store.
// Expired certificates fail validation and cannot trigger legacy fallback.
func (s *Store) Load() (*Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backend == nil {
		return nil, ErrUnavailable
	}
	p, err := s.loadPending()
	if err != nil {
		return nil, err
	}
	defer p.close()
	return s.loadIdentity(p)
}

// Enroll persists locally generated keys before the first HTTPS request. A retry
// must present the identical bootstrap and uses exactly the winning stored keys.
// Server roots are separately authorized HTTPS roots; nil means system roots.
// A response never supplies HTTPS trust. No automatic retry or legacy fallback
// occurs, and neither immutable record is deleted after activation.
func (s *Store) Enroll(ctx context.Context, bootstrap Bootstrap, roots *x509.CertPool) (*Identity, error) {
	if !bootstrap.valid() {
		return nil, ErrUnavailable
	}
	client, err := enrollment.NewHTTPClient(bootstrap.Origin, roots)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer client.CloseIdleConnections()
	return s.enroll(ctx, bootstrap, client.Claim)
}

type claimFunc func(context.Context, enrollment.Request) (*enrollment.Response, error)

func (s *Store) enroll(ctx context.Context, bootstrap Bootstrap, claim claimFunc) (*Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backend == nil || !bootstrap.valid() || claim == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := s.loadPending()
	if errors.Is(err, ErrMissing) {
		keys, generationErr := enrollment.GenerateKeys()
		if generationErr != nil {
			return nil, ErrUnavailable
		}
		data, encodeErr := encodePending(bootstrap, keys)
		releaseKeys(keys)
		if encodeErr != nil {
			return nil, ErrUnavailable
		}
		if err = ctx.Err(); err == nil {
			err = s.backend.Create(pendingRecord, data)
		}
		clear(data)
		if err != nil && !errors.Is(err, ErrExists) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrUnavailable
		}
		// Even the winner reloads: only persisted keys may reach the network.
		p, err = s.loadPending()
	}
	if err != nil {
		return nil, err
	}
	defer p.close()
	if p.bootstrap != bootstrap {
		return nil, ErrConflict
	}
	identity, err := s.loadIdentity(p)
	if !errors.Is(err, ErrPending) {
		return identity, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	request, err := p.keys.Request(bootstrap.Invitation, bootstrap.Platform, bootstrap.Architecture, bootstrap.DeviceName)
	if err != nil {
		return nil, ErrUnavailable
	}
	response, err := claim(ctx, *request)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, enrollment.ErrInvalidResponse
	}
	if _, err = enrollment.ValidateResponse(*response, bootstrap.Origin, &p.keys.Certificate.PublicKey, time.Now()); err != nil {
		return nil, err
	}
	data, err := encodeIdentity(p.digest, *response)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(data)
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = s.backend.Create(identityRecord, data); err != nil && !errors.Is(err, ErrExists) {
		return nil, ErrUnavailable
	}
	// A racing claim can publish first. Return that complete validated result,
	// never an uncommitted network response or a partially written local state.
	return s.loadIdentity(p)
}

type pending struct {
	bootstrap Bootstrap
	keys      *enrollment.Keys
	digest    [sha256.Size]byte
}

func (p *pending) close() { releaseKeys(p.keys); p.keys = nil }

func (s *Store) loadPending() (*pending, error) {
	data, err := s.backend.Load(pendingRecord)
	if errors.Is(err, ErrMissing) {
		other, otherErr := s.backend.Load(identityRecord)
		clear(other)
		if errors.Is(otherErr, ErrMissing) {
			return nil, ErrMissing
		}
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(data)
	return decodePending(data)
}

func (s *Store) loadIdentity(p *pending) (*Identity, error) {
	data, err := s.backend.Load(identityRecord)
	if errors.Is(err, ErrMissing) {
		return nil, ErrPending
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(data)
	response, err := decodeIdentity(data, p.digest)
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, err = enrollment.ValidateResponse(response, p.bootstrap.Origin, &p.keys.Certificate.PublicKey, time.Now()); err != nil {
		return nil, ErrUnavailable
	}
	identity := &Identity{Keys: p.keys, Response: response, Origin: p.bootstrap.Origin, ReleaseDigest: p.bootstrap.ReleaseDigest, Platform: p.bootstrap.Platform, Architecture: p.bootstrap.Architecture}
	p.keys = nil // transfer ownership, including when returning a competing result
	return identity, nil
}
