package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
)

type renewalFixture struct {
	backend                     NativeBackend
	store                       *Store
	original                    *Identity
	issuer                      *fixtureIssuer
	now                         time.Time
	server                      *httptest.Server
	roots                       *x509.CertPool
	mu                          sync.Mutex
	source                      enrollment.RenewalSource
	prepared                    map[string]*enrollment.PreparedIdentityRenewal
	targets                     map[string]*enrollment.RenewalConfirmationTarget
	confirmed                   map[string]*enrollment.ConfirmedIdentityRenewal
	preparations, confirmations int
	losePrepare, loseConfirm    atomic.Bool
}

func newRenewalFixture(t *testing.T, backend NativeBackend, platform string) *renewalFixture {
	t.Helper()
	f := &renewalFixture{backend: backend, issuer: newFixtureIssuer(t), now: time.Now().UTC(), prepared: make(map[string]*enrollment.PreparedIdentityRenewal), targets: make(map[string]*enrollment.RenewalConfirmationTarget), confirmed: make(map[string]*enrollment.ConfirmedIdentityRenewal)}
	// Extend only the synthetic issuer so historical-generation tests can cross
	// the original leaf's expiry without expiring their independently owned CA.
	ca := *f.issuer.ca
	ca.NotAfter = f.now.Add(365 * 24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &ca, &ca, &f.issuer.key.PublicKey, f.issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	f.issuer.ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != "POST" {
			t.Error("renewal did not use the native HTTP/2 contract")
			http.Error(w, "invalid", 400)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, enrollment.MaxRenewalRequestBytes+1))
		if err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		var result any
		switch r.URL.Path {
		case enrollment.IdentityRenewalPath(f.original.Response.DeviceID, "prepare"):
			request, decodeErr := enrollment.DecodeRenewalRequest(body)
			if decodeErr != nil {
				http.Error(w, "invalid", 400)
				return
			}
			p, state, stateErr := f.store.renewalState()
			if stateErr != nil {
				t.Error("prepare proof preceded durable native candidate state")
				http.Error(w, "invalid state", 503)
				return
			}
			proof, proofErr := enrollment.ValidateRenewalProof(*request, state.source, f.now)
			valid := proofErr == nil && state.pending != nil && state.pending.request.RequestID == request.RequestID && state.pending.keys.Certificate.PublicKey.Equal(proof.CertificateKey)
			p.close()
			state.close()
			if !valid {
				t.Error("prepare proof did not use the durable native winner")
				http.Error(w, "invalid state", 503)
				return
			}
			result, err = f.prepare(r.Context(), *request, enrollment.RenewalSource{})
			if err == nil && f.losePrepare.Swap(false) {
				err = enrollment.ErrEnrollmentBusy
			}
		case enrollment.IdentityRenewalPath(f.original.Response.DeviceID, "confirm"):
			request, decodeErr := enrollment.DecodeRenewalConfirmation(body)
			if decodeErr != nil {
				http.Error(w, "invalid", 400)
				return
			}
			p, state, stateErr := f.store.renewalState()
			if stateErr != nil {
				t.Error("confirmation proof preceded durable native decision")
				http.Error(w, "invalid state", 503)
				return
			}
			valid := state.pending != nil && state.pending.decision != nil && state.pending.decision.Action == "confirm" && state.pending.target != nil && enrollment.ValidateRenewalConfirmation(*request, *state.pending.target, f.now) == nil
			p.close()
			state.close()
			if !valid {
				t.Error("confirmation proof did not bind the durable native decision")
				http.Error(w, "invalid state", 503)
				return
			}
			result, err = f.confirm(r.Context(), *request, enrollment.RenewalConfirmationTarget{})
			if err == nil && f.loseConfirm.Swap(false) {
				err = enrollment.ErrEnrollmentBusy
			}
		default:
			http.Error(w, "invalid", 404)
			return
		}
		if err != nil {
			http.Error(w, "temporarily unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	f.server.EnableHTTP2 = true
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.server.Certificate())
	f.store = f.restarted()
	bootstrap := testBootstrap()
	bootstrap.Platform, bootstrap.Origin = platform, f.server.URL
	f.original, err = f.store.enroll(t.Context(), bootstrap, func(_ context.Context, request enrollment.Request) (*enrollment.Response, error) {
		return f.issuer.claim(bootstrap.Origin, request)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.original.Close() })
	cert, err := historicalResponse(f.original.Response, f.original.Origin, &f.original.Keys.Certificate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f.source, err = renewalSource(f.original, cert)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *renewalFixture) restarted() *Store {
	return &Store{backend: f.backend, renewalClock: func() time.Time { return f.now }}
}

func (f *renewalFixture) prepare(ctx context.Context, request enrollment.RenewalRequest, _ enrollment.RenewalSource) (*enrollment.PreparedIdentityRenewal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proof, err := enrollment.ValidateRenewalProof(request, f.source, f.now)
	if err != nil {
		return nil, err
	}
	if prepared := f.prepared[request.RequestID]; prepared != nil {
		copy := *prepared
		return &copy, nil
	}
	for id, prepared := range f.prepared {
		if f.confirmed[id] == nil && prepared.SourceCertificateHash == request.SourceCertificateHash && prepared.ExpiresAt.After(f.now) {
			return nil, enrollment.ErrIdentityRenewalPending
		}
	}
	old, _ := x509.ParseCertificate(f.source.Certificate)
	leaf := *old
	leaf.SerialNumber = big.NewInt(int64(100 + f.preparations))
	leaf.NotBefore, leaf.NotAfter = f.now.Add(-5*time.Minute).Truncate(time.Second), old.NotAfter.Add(72*time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &leaf, f.issuer.ca, proof.CertificateKey, f.issuer.key)
	if err != nil {
		return nil, err
	}
	response := f.original.Response
	response.Certificate, response.ExpiresAt = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), leaf.NotAfter
	expires := f.now.Add(enrollment.RenewalPreparationLifetime)
	if old.NotAfter.Before(expires) {
		expires = old.NotAfter
	}
	prepared := &enrollment.PreparedIdentityRenewal{ID: request.RequestID, SourceCertificateHash: request.SourceCertificateHash, ExpiresAt: expires, Response: response}
	target, err := enrollment.ValidatePreparedIdentityRenewal(*prepared, request, f.source, f.now)
	if err != nil {
		return nil, err
	}
	f.prepared[request.RequestID], f.targets[request.RequestID] = prepared, target
	f.preparations++
	copy := *prepared
	return &copy, nil
}

func (f *renewalFixture) confirm(ctx context.Context, request enrollment.RenewalConfirmation, _ enrollment.RenewalConfirmationTarget) (*enrollment.ConfirmedIdentityRenewal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target := f.targets[request.RequestID]
	if target == nil || enrollment.ValidateRenewalConfirmation(request, *target, f.now) != nil {
		return nil, enrollment.ErrIdentityRenewalDenied
	}
	if result := f.confirmed[request.RequestID]; result != nil {
		if renewalDigest(f.source.Certificate) != result.CertificateHash {
			return nil, enrollment.ErrIdentityRenewalDenied
		}
		copy := *result
		return &copy, nil
	}
	if renewalDigest(f.source.Certificate) != target.SourceCertificateHash || !f.prepared[request.RequestID].ExpiresAt.After(f.now) {
		return nil, enrollment.ErrIdentityRenewalDenied
	}
	f.source = target.Candidate
	result := &enrollment.ConfirmedIdentityRenewal{ID: request.RequestID, DeviceID: request.DeviceID, CertificateHash: request.CertificateHash, ConfirmedAt: f.now}
	f.confirmed[request.RequestID] = result
	f.confirmations++
	copy := *result
	return &copy, nil
}

func runDurableIdentityRenewal(t *testing.T, backend NativeBackend) {
	t.Helper()
	f := newRenewalFixture(t, backend, "macos")
	checkpoint, err := f.store.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	before := make(map[string][]byte)
	for _, name := range []string{pendingRecord, identityRecord} {
		data, err := backend.Load(name)
		if err != nil {
			t.Fatal(err)
		}
		before[name] = data
		defer clear(data)
	}
	f.losePrepare.Store(true)
	if prepared, err := f.store.PrepareRenewal(t.Context(), f.roots); prepared != nil || !errors.Is(err, enrollment.ErrEnrollmentBusy) {
		t.Fatal("lost preparation reply was activated", err)
	}
	status, err := f.restarted().RenewalStatus()
	if err != nil || status == nil || status.Stage != "candidate" {
		t.Fatal("candidate keys/request were not durable before HTTPS", err)
	}
	old, err := f.store.Load()
	if err != nil || old.Response != f.original.Response {
		t.Fatal("preparation retired original keys", err)
	}
	old.Close()
	prepared, err := f.restarted().PrepareRenewal(t.Context(), f.roots)
	if err != nil || prepared.ID != status.RequestID || f.preparations != 1 {
		t.Fatal("preparation retry changed candidate", err)
	}
	f.loseConfirm.Store(true)
	if identity, err := f.restarted().ConfirmRenewal(t.Context(), prepared.ID, f.roots); identity != nil || !errors.Is(err, enrollment.ErrEnrollmentBusy) {
		t.Fatal("lost activation reply produced an identity", err)
	}
	if _, err := f.store.Load(); !errors.Is(err, ErrRenewalHandoff) {
		t.Fatal("ambiguous activation fell back to original keys", err)
	}
	if err := f.store.AbandonRenewal(prepared.ID); !errors.Is(err, ErrRenewalHandoff) {
		t.Fatal("confirmation intent was abandoned", err)
	}
	if _, err := f.store.PrepareRenewal(t.Context(), f.roots); !errors.Is(err, ErrRenewalHandoff) {
		t.Fatal("ambiguous activation replaced its candidate", err)
	}
	status, err = f.restarted().RenewalStatus()
	if err != nil || status == nil || status.Stage != "confirming" || status.RequestID != prepared.ID {
		t.Fatal("lost confirmation decision", err)
	}
	active, err := f.restarted().ConfirmRenewal(t.Context(), prepared.ID, f.roots)
	if err != nil {
		t.Fatal("restart did not recover committed candidate", err)
	}
	defer active.Close()
	if active.Response != prepared.Response || active.Response.DeviceID != f.original.Response.DeviceID || active.Keys.Certificate.PublicKey.Equal(&f.original.Keys.Certificate.PublicKey) || f.confirmations != 1 {
		t.Fatal("handoff changed identity or repeated activation")
	}
	loaded, err := f.restarted().Load()
	if err != nil || loaded.Response != active.Response {
		t.Fatal("durable active generation was not selected", err)
	}
	loaded.Close()
	if _, err := active.Keys.Broker.PublicKey(); err != nil {
		t.Fatal("closing another load wiped active keys")
	}
	afterCheckpoint, err := f.store.Checkpoint()
	if err != nil || checkpoint != afterCheckpoint {
		t.Fatal("renewal reset the release checkpoint", err)
	}
	for name, original := range before {
		after, err := backend.Load(name)
		if err != nil || !bytes.Equal(original, after) {
			t.Fatal("renewal rewrote an installation anchor", name, err)
		}
		clear(after)
	}
	if status, err := f.store.RenewalStatus(); err != nil || status != nil {
		t.Fatal("confirmed generation remained pending", err)
	}
}

func TestIdentityRenewalNativeTransportRetainsKeysAndAmbiguousDecisions(t *testing.T) {
	runDurableIdentityRenewal(t, newMemoryBackend(t))
}

func TestIdentityRenewalPublicationFailureAndLostNativeCommit(t *testing.T) {
	for _, stage := range renewalStages {
		for _, committed := range []bool{false, true} {
			t.Run(stage+map[bool]string{false: " before commit", true: " after commit"}[committed], func(t *testing.T) {
				b := newMemoryBackend(t)
				f := newRenewalFixture(t, b, "windows")
				var prepared *enrollment.PreparedIdentityRenewal
				var err error
				if stage == "decision" || stage == "activated" {
					prepared, err = f.store.prepareRenewal(t.Context(), f.prepare)
					if err != nil {
						t.Fatal(err)
					}
				}
				b.failCreate, b.commitBeforeError = renewalRecord(stage, 1), committed
				if prepared == nil {
					_, err = f.store.prepareRenewal(t.Context(), f.prepare)
				} else {
					_, err = f.store.confirmRenewal(t.Context(), prepared.ID, f.confirm)
				}
				if !errors.Is(err, ErrUnavailable) {
					t.Fatal("failed native publication returned success", err)
				}
				identity, loadErr := f.restarted().Load()
				if stage == "activated" && committed {
					if loadErr != nil || identity.Response == f.original.Response {
						t.Fatal("committed activation was lost", loadErr)
					}
				} else if stage == "activated" || stage == "decision" && committed {
					if identity != nil || !errors.Is(loadErr, ErrRenewalHandoff) {
						t.Fatal("ambiguous decision returned old keys", loadErr)
					}
				} else if loadErr != nil || identity.Response != f.original.Response {
					t.Fatal("unconfirmed candidate retired old identity", loadErr)
				}
				if identity != nil {
					identity.Close()
				}
				if stage == "candidate" && f.preparations != 0 || stage == "decision" && f.confirmations != 0 {
					t.Fatal("network proof preceded its durable decision")
				}
				b.failCreate, b.commitBeforeError = "", false
				if prepared == nil {
					prepared, err = f.restarted().prepareRenewal(t.Context(), f.prepare)
					if err != nil {
						t.Fatal(err)
					}
				}
				active, err := f.restarted().confirmRenewal(t.Context(), prepared.ID, f.confirm)
				if err != nil {
					t.Fatal("retained candidate did not recover", err)
				}
				active.Close()
				if f.preparations != 1 || f.confirmations != 1 {
					t.Fatal("recovery duplicated issuance or activation")
				}
			})
		}
	}
}

func TestIdentityRenewalRecoversAfterSourceAndPreparationExpiryAndPreservesLaterGeneration(t *testing.T) {
	f := newRenewalFixture(t, newMemoryBackend(t), "windows")
	prepared, err := f.store.prepareRenewal(t.Context(), f.prepare)
	if err != nil {
		t.Fatal(err)
	}
	lost := func(ctx context.Context, request enrollment.RenewalConfirmation, target enrollment.RenewalConfirmationTarget) (*enrollment.ConfirmedIdentityRenewal, error) {
		_, err := f.confirm(ctx, request, target)
		if err != nil {
			return nil, err
		}
		return nil, enrollment.ErrEnrollmentBusy
	}
	if _, err := f.store.confirmRenewal(t.Context(), prepared.ID, lost); !errors.Is(err, enrollment.ErrEnrollmentBusy) {
		t.Fatal(err)
	}
	f.now = prepared.ExpiresAt.Add(time.Hour)
	if _, err := f.restarted().Load(); !errors.Is(err, ErrRenewalHandoff) {
		t.Fatal("expiry cleared confirmation uncertainty", err)
	}
	if err := f.restarted().AbandonRenewal(prepared.ID); !errors.Is(err, ErrRenewalHandoff) {
		t.Fatal("expiry permitted abandonment", err)
	}
	active, err := f.restarted().confirmRenewal(t.Context(), prepared.ID, f.confirm)
	if err != nil {
		t.Fatal("expired source prevented recovery of committed candidate", err)
	}
	active.Close()
	next, err := f.store.prepareRenewal(t.Context(), f.prepare)
	if err != nil || next.ID == prepared.ID {
		t.Fatal("next generation could not be prepared", err)
	}
	active, err = f.store.confirmRenewal(t.Context(), next.ID, f.confirm)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if _, err := f.restarted().confirmRenewal(t.Context(), prepared.ID, f.confirm); !errors.Is(err, ErrRenewalConflict) {
		t.Fatal("older confirmation could replace a later generation", err)
	}
	loaded, err := f.restarted().Load()
	if err != nil || !reflect.DeepEqual(loaded.Response, active.Response) {
		t.Fatal("history lost the current generation", err)
	}
	loaded.Close()
	if len(active.certificates) != 3 || f.confirmations != 2 {
		t.Fatal("renewal history omitted a generation")
	}
}

func TestIdentityRenewalRejectsUnboundedRecordNames(t *testing.T) {
	for _, stage := range renewalStages {
		for _, suffix := range []string{"000", "129", "1", "+01", "0001", "001/../identity"} {
			if validRecord("renewal-" + stage + "-v1-" + suffix) {
				t.Fatal("renewal accepted an unbounded record name")
			}
		}
	}
	if validRecord(strings.Repeat("renewal-", 1000)) {
		t.Fatal("unknown protected record was accepted")
	}
}
