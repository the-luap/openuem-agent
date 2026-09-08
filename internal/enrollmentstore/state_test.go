package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
)

// The memory backend exists only in tests. Production Open always requires the
// platform's protected native storage and has no in-memory/plaintext fallback.
type memoryBackend struct {
	mu                sync.Mutex
	records           map[string][]byte
	failCreate        string
	commitBeforeError bool
	closed            bool
}

func newMemoryBackend(t *testing.T) *memoryBackend {
	t.Helper()
	b := &memoryBackend{records: make(map[string][]byte)}
	t.Cleanup(func() {
		for _, data := range b.records {
			clear(data)
		}
	})
	return b
}
func (b *memoryBackend) Load(name string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrUnavailable
	}
	data, ok := b.records[name]
	if !ok {
		return nil, ErrMissing
	}
	return bytes.Clone(data), nil
}
func (b *memoryBackend) Create(name string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrUnavailable
	}
	if _, ok := b.records[name]; ok {
		return ErrExists
	}
	if b.failCreate == name && !b.commitBeforeError {
		return ErrUnavailable
	}
	b.records[name] = bytes.Clone(data)
	if b.failCreate == name {
		return ErrUnavailable
	}
	return nil
}
func (b *memoryBackend) Close() error { b.mu.Lock(); defer b.mu.Unlock(); b.closed = true; return nil }

func testBootstrap() Bootstrap {
	return Bootstrap{Origin: "https://uem.example.test", Invitation: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{13}, 32)), Platform: "windows", Architecture: "amd64", DeviceName: "Isolated endpoint", ReleaseDigest: strings.Repeat("b", 64)}
}

type fixtureIssuer struct {
	mu       sync.Mutex
	ca       *x509.Certificate
	key      *ecdsa.PrivateKey
	response *enrollment.Response
	binding  string
	requests int
}

func newFixtureIssuer(t *testing.T) *fixtureIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Isolated endpoint issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &fixtureIssuer{ca: ca, key: key}
}

func (f *fixtureIssuer) claim(origin string, request enrollment.Request) (*enrollment.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	proof, err := enrollment.Validate(request)
	if err != nil {
		return nil, err
	}
	f.requests++
	if f.response != nil {
		if proof.KeyBinding != f.binding {
			return nil, enrollment.ErrEnrollmentUnavailable
		}
		response := *f.response
		return &response, nil
	}
	now := time.Now().UTC().Truncate(time.Second)
	id := "6f73f916-8aaf-4cd1-92e9-c8cbb11028ba"
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{{Scheme: "urn", Opaque: "openuem:agent:" + id}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, proof.CertificateKey, f.key)
	if err != nil {
		return nil, err
	}
	f.binding = proof.KeyBinding
	f.response = &enrollment.Response{Version: 1, DeviceID: id, TenantID: 3, SiteID: 4, Endpoint: "wss" + strings.TrimPrefix(origin, "https") + "/agent-channel", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Authority: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})), ExpiresAt: leaf.NotAfter}
	response := *f.response
	return &response, nil
}

func runDurableEnrollmentRecovery(t *testing.T, backend NativeBackend) {
	t.Helper()
	issuer := newFixtureIssuer(t)
	bootstrap := testBootstrap()
	var count atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != http.MethodPost || r.URL.Path != "/enroll/desktop/"+bootstrap.Invitation+"/claim" {
			t.Error("unexpected native enrollment transport")
			http.Error(w, "invalid", 400)
			return
		}
		var request enrollment.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		// Inspect the protected winning keys at the exact first-network boundary.
		persisted, err := backend.Load(pendingRecord)
		if err != nil {
			t.Error("request preceded durable pending keys", err)
			return
		}
		p, err := decodePending(persisted)
		clear(persisted)
		if err != nil {
			t.Error(err)
			return
		}
		defer p.close()
		public, err := p.keys.Broker.PublicKey()
		proof, proofErr := enrollment.Validate(request)
		if err != nil || proofErr != nil || public != request.BrokerKey || proof.CertificateKey.N.Cmp(p.keys.Certificate.N) != 0 {
			t.Error("claim did not use stored keys")
			return
		}
		response, err := issuer.claim(bootstrap.Origin, request)
		if err != nil {
			t.Error(err)
			return
		}
		if count.Add(1) == 1 {
			// The server committed issuance but its reply was lost. The client
			// cannot know whether a one-use invitation was consumed.
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "10000")
			w.Write([]byte("{"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	bootstrap.Origin = server.URL
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	store := &Store{backend: backend}
	if _, err := store.Load(); !errors.Is(err, ErrMissing) {
		t.Fatal("new installation was not empty", err)
	}
	if identity, err := store.Enroll(context.Background(), bootstrap, roots); err == nil || identity != nil {
		t.Fatal("lost reply activated an identity")
	}
	if _, err := store.Load(); !errors.Is(err, ErrPending) {
		t.Fatal("lost reply did not retain pending state", err)
	}
	// A new state-machine instance has no in-memory copy of the generated keys.
	restarted := &Store{backend: backend}
	identity, err := restarted.Enroll(context.Background(), bootstrap, roots)
	if err != nil {
		t.Fatal("same-key restart could not recover issuance", err)
	}
	defer identity.Close()
	if count.Load() != 2 || issuer.requests != 2 {
		t.Fatal("recovery sent an unexpected number of claims")
	}
	loaded, err := restarted.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Response != identity.Response {
		t.Fatal("runtime load changed the issued identity")
	}
	loaded.Close()
	if _, err := identity.Keys.Request(bootstrap.Invitation, bootstrap.Platform, bootstrap.Architecture, bootstrap.DeviceName); err != nil {
		t.Fatal("closing a separate load wiped live identity keys", err)
	}
	again, err := restarted.Enroll(context.Background(), bootstrap, roots)
	if err != nil {
		t.Fatal(err)
	}
	again.Close()
	if count.Load() != 2 {
		t.Fatal("completed enrollment consumed another invitation use")
	}
	if data, err := json.Marshal(identity); err == nil || len(data) != 0 {
		t.Fatal("identity private keys could be serialized")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", bootstrap, bootstrap), bootstrap.Invitation) {
		t.Fatal("formatted bootstrap exposed its invitation")
	}
}

func TestDurableEnrollmentRecoversACommittedClaimWithALostHTTPSResponse(t *testing.T) {
	runDurableEnrollmentRecovery(t, newMemoryBackend(t))
}

func preparePending(t *testing.T, b *memoryBackend, bootstrap Bootstrap) {
	t.Helper()
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseKeys(keys)
	data, err := encodePending(bootstrap, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if err := b.Create(pendingRecord, data); err != nil {
		t.Fatal(err)
	}
}

func TestPendingPublicationFailureCannotSendAClaim(t *testing.T) {
	b := newMemoryBackend(t)
	b.failCreate = pendingRecord
	s := &Store{backend: b}
	called := false
	_, err := s.enroll(context.Background(), testBootstrap(), func(context.Context, enrollment.Request) (*enrollment.Response, error) {
		called = true
		return nil, nil
	})
	if !errors.Is(err, ErrUnavailable) || called || len(b.records) != 0 {
		t.Fatal("failed persistence reached the issuer", err)
	}
}

func TestCompletePublicationFailureResumesTheSameKeys(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			b := newMemoryBackend(t)
			b.failCreate = identityRecord
			b.commitBeforeError = committed
			s := &Store{backend: b}
			config := testBootstrap()
			issuer := newFixtureIssuer(t)
			claim := func(_ context.Context, r enrollment.Request) (*enrollment.Response, error) {
				return issuer.claim(config.Origin, r)
			}
			if identity, err := s.enroll(context.Background(), config, claim); identity != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("unconfirmed publication was returned", err)
			}
			before := sha256.Sum256(b.records[pendingRecord])
			b.failCreate = ""
			identity, err := (&Store{backend: b}).enroll(context.Background(), config, claim)
			if err != nil {
				t.Fatal(err)
			}
			identity.Close()
			want := 2
			if committed {
				want = 1
			}
			if issuer.requests != want || sha256.Sum256(b.records[pendingRecord]) != before {
				t.Fatal("publication recovery changed keys or sent unnecessary claims")
			}
		})
	}
}

func TestPendingBootstrapCannotBeReplacedOrRedirected(t *testing.T) {
	b := newMemoryBackend(t)
	config := testBootstrap()
	preparePending(t, b, config)
	before := sha256.Sum256(b.records[pendingRecord])
	for _, change := range []func(*Bootstrap){
		func(b *Bootstrap) { b.Origin = "https://other.example.test" },
		func(b *Bootstrap) { b.Invitation = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{14}, 32)) },
		func(b *Bootstrap) { b.Platform = "macos" },
		func(b *Bootstrap) { b.Architecture = "arm64" },
		func(b *Bootstrap) { b.DeviceName = "Changed name" },
		func(b *Bootstrap) { b.ReleaseDigest = strings.Repeat("a", 64) },
	} {
		other := config
		change(&other)
		_, err := (&Store{backend: b}).enroll(context.Background(), other, func(context.Context, enrollment.Request) (*enrollment.Response, error) {
			t.Error("conflicting bootstrap sent a claim")
			return nil, nil
		})
		if !errors.Is(err, ErrConflict) || sha256.Sum256(b.records[pendingRecord]) != before {
			t.Fatal("bootstrap replaced pending state", err)
		}
	}
}

func TestConcurrentEnrollmentsUseOneDurableKeyPairAndIdentity(t *testing.T) {
	b := newMemoryBackend(t)
	config := testBootstrap()
	issuer := newFixtureIssuer(t)
	var work sync.WaitGroup
	results := make(chan *Identity, 4)
	for range 4 {
		work.Go(func() {
			identity, err := (&Store{backend: b}).enroll(context.Background(), config, func(_ context.Context, r enrollment.Request) (*enrollment.Response, error) {
				return issuer.claim(config.Origin, r)
			})
			if err != nil {
				t.Error(err)
			}
			results <- identity
		})
	}
	work.Wait()
	close(results)
	for identity := range results {
		if identity == nil {
			continue
		}
		if identity.Response != *issuer.response {
			t.Error("competing caller received a different identity")
		}
		identity.Close()
	}
	if len(b.records) != 2 || issuer.response == nil {
		t.Fatal("concurrent enrollment did not publish two complete records")
	}
}

func TestExistingIncompleteOrCorruptStateFailsClosed(t *testing.T) {
	source := newMemoryBackend(t)
	config := testBootstrap()
	preparePending(t, source, config)
	issuer := newFixtureIssuer(t)
	identity, err := (&Store{backend: source}).enroll(context.Background(), config, func(_ context.Context, r enrollment.Request) (*enrollment.Response, error) {
		return issuer.claim(config.Origin, r)
	})
	if err != nil {
		t.Fatal(err)
	}
	identity.Close()
	for _, name := range []string{"orphan identity", "corrupt pending", "corrupt identity", "binding mismatch", "wrong response origin", "trailing pending data", "trailing identity data", "duplicate JSON field"} {
		t.Run(name, func(t *testing.T) {
			b := newMemoryBackend(t)
			for key, data := range source.records {
				b.records[key] = bytes.Clone(data)
			}
			switch name {
			case "orphan identity":
				clear(b.records[pendingRecord])
				delete(b.records, pendingRecord)
			case "corrupt pending":
				b.records[pendingRecord][0] ^= 1
			case "corrupt identity":
				b.records[identityRecord][0] ^= 1
			case "binding mismatch":
				b.records[identityRecord][len(identityMagic)+4] ^= 1
			case "wrong response origin":
				response := *issuer.response
				response.Endpoint = "wss://other.example.test/agent-channel"
				data, err := encodeIdentity(sha256.Sum256(b.records[pendingRecord]), response)
				if err != nil {
					t.Fatal(err)
				}
				clear(b.records[identityRecord])
				b.records[identityRecord] = data
			case "trailing pending data":
				b.records[pendingRecord] = append(b.records[pendingRecord], 0)
			case "trailing identity data":
				b.records[identityRecord] = append(b.records[identityRecord], 0)
			case "duplicate JSON field":
				fields, err := decodeFields(b.records[identityRecord], identityMagic, 2)
				if err != nil {
					t.Fatal(err)
				}
				duplicate := append([]byte(`{"version":1,`), fields[1][1:]...)
				data, err := encodeFields(identityMagic, fields[0], duplicate)
				if err != nil {
					t.Fatal(err)
				}
				clear(b.records[identityRecord])
				b.records[identityRecord] = data
			}
			s := &Store{backend: b}
			if _, err := s.Load(); !errors.Is(err, ErrUnavailable) {
				t.Fatal("corrupt state became empty/pending/active", err)
			}
			if _, err := s.enroll(context.Background(), config, func(context.Context, enrollment.Request) (*enrollment.Response, error) {
				t.Error("corrupt state sent a replacement claim")
				return nil, nil
			}); !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
		})
	}
}

func TestCanceledOrRejectedClaimsRetainTheOriginalPendingState(t *testing.T) {
	b := newMemoryBackend(t)
	config := testBootstrap()
	preparePending(t, b, config)
	before := sha256.Sum256(b.records[pendingRecord])
	s := &Store{backend: b}
	for _, failure := range []error{context.Canceled, enrollment.ErrEnrollmentUnavailable, enrollment.ErrEnrollmentBusy, enrollment.ErrInvalidResponse} {
		if _, err := s.enroll(context.Background(), config, func(context.Context, enrollment.Request) (*enrollment.Response, error) { return nil, failure }); !errors.Is(err, failure) {
			t.Fatal(err)
		}
		if len(b.records) != 1 || sha256.Sum256(b.records[pendingRecord]) != before {
			t.Fatal("rejected claim changed durable pending state")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.enroll(ctx, config, func(context.Context, enrollment.Request) (*enrollment.Response, error) {
		t.Error("canceled enrollment sent a claim")
		return nil, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	s.Close()
	if _, err := s.Load(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed store returned state", err)
	}
}

func TestPrivateRecordDecoderRejectsTruncationOverflowAndWrongStage(t *testing.T) {
	b := newMemoryBackend(t)
	preparePending(t, b, testBootstrap())
	data := b.records[pendingRecord]
	for _, end := range []int{0, len(pendingMagic) - 1, len(pendingMagic) + 2, len(data) - 1} {
		if _, err := decodePending(data[:end]); !errors.Is(err, ErrUnavailable) {
			t.Fatal("truncated state was accepted", end)
		}
	}
	overflow := bytes.Clone(data)
	defer clear(overflow)
	binary.BigEndian.PutUint32(overflow[len(pendingMagic):], ^uint32(0))
	if _, err := decodePending(overflow); !errors.Is(err, ErrUnavailable) {
		t.Fatal("overflowing state was accepted")
	}
	if _, err := decodeIdentity(data, sha256.Sum256(data)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("pending state was interpreted as a completed identity")
	}
	p, err := decodePending(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	// Clearing the owned encoding must not wipe the decoded signing keys.
	copyData := bytes.Clone(data)
	decoded, err := decodePending(copyData)
	clear(copyData)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.close()
	if _, err := decoded.keys.Request(p.bootstrap.Invitation, p.bootstrap.Platform, p.bootstrap.Architecture, p.bootstrap.DeviceName); err != nil {
		t.Fatal("decoded key aliases the cleared record buffer", err)
	}
}

func TestUnboundIssuanceCannotPublishAnIdentity(t *testing.T) {
	b := newMemoryBackend(t)
	config := testBootstrap()
	preparePending(t, b, config)
	issuer := newFixtureIssuer(t)
	for _, variant := range []string{"nil", "wrong origin", "wrong local key"} {
		t.Run(variant, func(t *testing.T) {
			_, err := (&Store{backend: b}).enroll(context.Background(), config, func(_ context.Context, request enrollment.Request) (*enrollment.Response, error) {
				if variant == "nil" {
					return nil, nil
				}
				if variant == "wrong local key" {
					keys, err := enrollment.GenerateKeys()
					if err != nil {
						return nil, err
					}
					defer releaseKeys(keys)
					other, err := keys.Request(config.Invitation, config.Platform, config.Architecture, config.DeviceName)
					if err != nil {
						return nil, err
					}
					return newFixtureIssuer(t).claim(config.Origin, *other)
				}
				response, err := issuer.claim(config.Origin, request)
				if err != nil {
					return nil, err
				}
				response.Endpoint = "wss://other.example.test/agent-channel"
				return response, nil
			})
			if !errors.Is(err, enrollment.ErrInvalidResponse) || len(b.records) != 1 {
				t.Fatal("unbound response was published", err)
			}
		})
	}
}

func TestStoreCloseJoinsAnActiveClaimAfterCallerCancellation(t *testing.T) {
	b := newMemoryBackend(t)
	config := testBootstrap()
	preparePending(t, b, config)
	s := &Store{backend: b}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := s.enroll(ctx, config, func(ctx context.Context, _ enrollment.Request) (*enrollment.Response, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("claim did not start")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("store closed its backend while the claim was active")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("claim did not stop")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("store did not join the completed claim")
	}
	if len(b.records) != 1 {
		t.Fatal("shutdown discarded pending keys or activated an identity")
	}
}
