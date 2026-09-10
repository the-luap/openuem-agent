package enrollmentstore

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
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
	// Optional only for compatibility with the earlier explicitly configured
	// claim API. Signed bootstrap integration always sets all three fields.
	TenantID        int    `json:"tenant_id,omitempty"`
	SiteID          int    `json:"site_id,omitempty"`
	ReleaseSequence uint64 `json:"release_sequence,omitempty"`
	// Installed-agent admission binds these bytes before pending publication.
	// Both fields are absent in older records, which remain readable.
	AgentSize   int64  `json:"agent_size,omitempty"`
	AgentSHA256 string `json:"agent_sha256,omitempty"`
}

func (Bootstrap) String() string     { return "[individual enrollment bootstrap]" }
func (b Bootstrap) GoString() string { return b.String() }

func (b Bootstrap) valid() bool {
	digest, err := hex.DecodeString(b.ReleaseDigest)
	agentDigest, agentErr := hex.DecodeString(b.AgentSHA256)
	agentValid := b.AgentSize == 0 && b.AgentSHA256 == "" || b.AgentSize > 0 && b.AgentSize <= artifacts.MaxPackageSize && agentErr == nil && len(agentDigest) == sha256.Size && hex.EncodeToString(agentDigest) == b.AgentSHA256
	return enrollment.ValidOrigin(b.Origin) && enrollment.ValidToken(b.Invitation) &&
		(b.Platform == "windows" || b.Platform == "macos") &&
		(b.Architecture == "amd64" || b.Architecture == "arm64") &&
		len(b.DeviceName) <= 255 && utf8.ValidString(b.DeviceName) && !strings.ContainsAny(b.DeviceName, "\x00\r\n") &&
		err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == b.ReleaseDigest &&
		((b.TenantID == 0 && b.SiteID == 0) || (b.TenantID > 0 && b.SiteID > 0)) && b.ReleaseSequence <= math.MaxInt64 && agentValid
}

func (b Bootstrap) matchesScope(response enrollment.Response) bool {
	return b.TenantID == 0 || (b.TenantID == response.TenantID && b.SiteID == response.SiteID)
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
	AgentSize     int64
	AgentSHA256   string
	certificates  map[string]renewalCertificate
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
	mu           sync.RWMutex
	backend      NativeBackend
	renewalClock func() time.Time
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
// Expired current certificates fail validation and cannot trigger legacy fallback.
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

// Checkpoint returns the durable release selected before the first claim. Only
// an actually empty installation returns a zero checkpoint. Earlier records that
// lack a sequence remain loadable but cannot reset signed-bootstrap rollback
// checks to zero; their explicit migration is a separate operation.
func (s *Store) Checkpoint() (artifacts.Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backend == nil {
		return artifacts.Checkpoint{}, ErrUnavailable
	}
	p, err := s.loadPending()
	if errors.Is(err, ErrMissing) {
		return artifacts.Checkpoint{}, nil
	}
	if err != nil {
		return artifacts.Checkpoint{}, err
	}
	defer p.close()
	if p.bootstrap.ReleaseSequence == 0 {
		return artifacts.Checkpoint{}, ErrUnavailable
	}
	return artifacts.Checkpoint{Sequence: p.bootstrap.ReleaseSequence, Digest: p.bootstrap.ReleaseDigest}, nil
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
	return s.enrollAdmitted(ctx, bootstrap, claim, nil)
}

func (s *Store) enrollAdmitted(ctx context.Context, bootstrap Bootstrap, claim claimFunc, admission func(context.Context) error) (*Identity, error) {
	if s == nil || ctx == nil {
		return nil, ErrUnavailable
	}
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
		if err == nil && admission != nil {
			if err = admission(ctx); err != nil {
				identity.Close()
				return nil, err
			}
		}
		return identity, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	request, err := p.keys.Request(bootstrap.Invitation, bootstrap.Platform, bootstrap.Architecture, bootstrap.DeviceName)
	if err != nil {
		return nil, ErrUnavailable
	}
	if admission != nil {
		if err := admission(ctx); err != nil {
			return nil, err
		}
	}
	response, err := claim(ctx, *request)
	if err != nil {
		return nil, err
	}
	if response == nil || !bootstrap.matchesScope(*response) {
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
	if admission != nil {
		if err := admission(ctx); err != nil {
			return nil, err
		}
	}
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
		if errors.Is(otherErr, ErrMissing) && s.securityRecordsAbsent() {
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
	state, err := s.loadRenewalState(p)
	if err != nil {
		return nil, err
	}
	defer state.close()
	if state.pending != nil && state.pending.decision != nil && state.pending.decision.Action == "confirm" {
		return nil, ErrRenewalHandoff
	}
	if _, err := enrollment.ValidateResponse(state.identity.Response, state.identity.Origin, &state.identity.Keys.Certificate.PublicKey, s.renewalTime()); err != nil {
		return nil, ErrUnavailable
	}
	identity := state.identity
	state.identity = nil
	return identity, nil
}

func (s *Store) loadOriginalIdentity(p *pending) (*Identity, error) {
	data, err := s.backend.Load(identityRecord)
	if errors.Is(err, ErrMissing) {
		if !s.securityRecordsAbsent() {
			return nil, ErrUnavailable
		}
		return nil, ErrPending
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(data)
	response, err := decodeIdentity(data, p.digest)
	if err != nil || !p.bootstrap.matchesScope(response) {
		return nil, ErrUnavailable
	}
	if _, err = historicalResponse(response, p.bootstrap.Origin, &p.keys.Certificate.PublicKey); err != nil {
		return nil, ErrUnavailable
	}
	identity := &Identity{Keys: p.keys, Response: response, Origin: p.bootstrap.Origin, ReleaseDigest: p.bootstrap.ReleaseDigest, Platform: p.bootstrap.Platform, Architecture: p.bootstrap.Architecture, AgentSize: p.bootstrap.AgentSize, AgentSHA256: p.bootstrap.AgentSHA256}
	p.keys = nil // transfer ownership, including when returning a competing result
	return identity, nil
}

// A partial restore can lose both enrollment records and the journal anchor
// while retaining a later irreversible attempt. Inspect every bounded slot before
// treating missing enrollment state as empty or as a safely retryable claim.
// Native read errors also fail closed; no surviving data is rewritten or removed.
// Extend this inventory whenever another protected lifecycle record is introduced.
func (s *Store) securityRecordsAbsent() bool {
	for _, name := range []string{recipientRecord, rotationAnchorRecord} {
		data, err := s.backend.Load(name)
		clear(data)
		if !errors.Is(err, ErrMissing) {
			return false
		}
	}
	for ordinal := 1; ordinal <= enrollment.MaxRotationAttempts; ordinal++ {
		for _, result := range []bool{false, true} {
			data, err := s.backend.Load(rotationRecord(result, ordinal))
			clear(data)
			if !errors.Is(err, ErrMissing) {
				return false
			}
		}
	}
	for ordinal := 1; ordinal <= MaxIdentityRenewalAttempts; ordinal++ {
		for _, stage := range renewalStages {
			data, err := s.backend.Load(renewalRecord(stage, ordinal))
			clear(data)
			if !errors.Is(err, ErrMissing) {
				return false
			}
		}
	}
	return true
}
