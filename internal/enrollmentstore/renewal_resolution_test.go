package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
)

func (f *renewalFixture) resolve(ctx context.Context, request enrollment.RenewalResolution, _ enrollment.RenewalConfirmationTarget, _ enrollment.RenewalSource) (*enrollment.ResolvedIdentityRenewal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target := f.targets[request.RequestID]
	if target == nil || enrollment.ValidateRenewalResolution(request, *target, f.now) != nil {
		return nil, enrollment.ErrIdentityRenewalDenied
	}
	current, err := x509.ParseCertificate(f.source.Certificate)
	if err != nil || !current.NotAfter.After(f.now) {
		return nil, enrollment.ErrIdentityRenewalDenied
	}
	if confirmed := f.confirmed[request.RequestID]; confirmed != nil {
		if renewalDigest(f.source.Certificate) != confirmed.CertificateHash {
			return nil, enrollment.ErrIdentityRenewalDenied
		}
		return &enrollment.ResolvedIdentityRenewal{Version: 1, ID: request.RequestID, DeviceID: request.DeviceID, SourceCertificateHash: request.SourceCertificateHash, CertificateHash: request.CertificateHash, Outcome: "confirmed", ResolvedAt: confirmed.ConfirmedAt}, nil
	}
	if renewalDigest(f.source.Certificate) != target.SourceCertificateHash {
		return nil, enrollment.ErrIdentityRenewalDenied
	}
	if previous := f.resolved[request.RequestID]; previous != nil {
		copy := *previous
		return &copy, nil
	}
	result := &enrollment.ResolvedIdentityRenewal{Version: 1, ID: request.RequestID, DeviceID: request.DeviceID, SourceCertificateHash: request.SourceCertificateHash, CertificateHash: request.CertificateHash, Outcome: "cancelled", ResolvedAt: f.now}
	f.resolved[request.RequestID] = result
	f.resolutions++
	copy := *result
	return &copy, nil
}

func (f *renewalFixture) uncertainRenewal(t *testing.T, confirmed bool) string {
	t.Helper()
	prepared, err := f.store.PrepareRenewal(t.Context(), f.roots)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.store.confirmRenewal(t.Context(), prepared.ID, func(ctx context.Context, request enrollment.RenewalConfirmation, target enrollment.RenewalConfirmationTarget) (*enrollment.ConfirmedIdentityRenewal, error) {
		if confirmed {
			if _, err := f.confirm(ctx, request, target); err != nil {
				return nil, err
			}
		}
		return nil, enrollment.ErrEnrollmentBusy
	})
	if !errors.Is(err, enrollment.ErrEnrollmentBusy) {
		t.Fatal("fixture did not retain uncertain confirmation", err)
	}
	if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrRenewalHandoff) {
		t.Fatal("uncertain confirmation returned old credentials", err)
	}
	return prepared.ID
}

func runDurableIdentityRenewalResolution(t *testing.T, backend NativeBackend, confirmed bool) {
	t.Helper()
	f := newRenewalFixture(t, backend, "macos")
	checkpoint, err := f.store.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	id := f.uncertainRenewal(t, confirmed)
	f.loseResolve.Store(true)
	if identity, err := f.restarted().ResolveRenewal(t.Context(), id, f.roots); identity != nil || !errors.Is(err, enrollment.ErrEnrollmentBusy) {
		t.Fatal("lost resolution reply selected a generation", err)
	}
	if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrRenewalHandoff) {
		t.Fatal("lost resolution reply permitted fallback", err)
	}
	identity, err := f.restarted().ResolveRenewal(t.Context(), id, f.roots)
	if err != nil {
		t.Fatal("retained resolution could not recover", err)
	}
	defer identity.Close()
	if (identity.Response == f.original.Response) == confirmed {
		t.Fatal("resolution selected wrong generation")
	}
	if identity.ReleaseDigest != f.original.ReleaseDigest || identity.AgentSize != f.original.AgentSize || identity.AgentSHA256 != f.original.AgentSHA256 {
		t.Fatal("resolution changed installation anchors")
	}
	if after, err := f.restarted().Checkpoint(); err != nil || !reflect.DeepEqual(checkpoint, after) {
		t.Fatal("resolution changed installation checkpoint", err)
	}
	loaded, err := f.restarted().Load()
	if err != nil || loaded.Response != identity.Response {
		t.Fatal("resolution selection was not durable", err)
	}
	loaded.Close()
	if status, err := f.restarted().RenewalStatus(); err != nil || status != nil {
		t.Fatal("resolved attempt remained pending", err)
	}
	// Both outcomes retain the actual resolution proof, never fabricated
	// confirmation evidence, and are locally idempotent without another request.
	data, err := backend.Load(renewalRecord("resolved", 1))
	if err != nil || len(data) == 0 {
		t.Fatal("resolution evidence was not protected", err)
	}
	clear(data)
	if data, err := backend.Load(renewalRecord("activated", 1)); !errors.Is(err, ErrMissing) || data != nil {
		clear(data)
		t.Fatal("resolution fabricated a confirmation record", err)
	}
	again, err := f.restarted().resolveRenewal(t.Context(), id, func(context.Context, enrollment.RenewalResolution, enrollment.RenewalConfirmationTarget, enrollment.RenewalSource) (*enrollment.ResolvedIdentityRenewal, error) {
		t.Error("durable resolution repeated HTTPS")
		return nil, context.Canceled
	})
	if err != nil || again.Response != identity.Response {
		t.Fatal("durable resolution could not be recovered locally", err)
	}
	again.Close()
	if !confirmed {
		if _, err := f.restarted().ConfirmRenewal(t.Context(), id, f.roots); !errors.Is(err, ErrRenewalConflict) {
			t.Fatal("cancelled decision was replaced by confirmation", err)
		}
		next, err := f.restarted().PrepareRenewal(t.Context(), f.roots)
		if err != nil || next.ID == id {
			t.Fatal("cancelled attempt did not release next local attempt", err)
		}
		if _, err := f.restarted().ResolveRenewal(t.Context(), id, f.roots); !errors.Is(err, ErrRenewalConflict) {
			t.Fatal("historical resolution interfered with next attempt", err)
		}
	} else {
		next, err := f.restarted().PrepareRenewal(t.Context(), f.roots)
		if err != nil {
			t.Fatal(err)
		}
		later, err := f.restarted().ConfirmRenewal(t.Context(), next.ID, f.roots)
		if err != nil {
			t.Fatal(err)
		}
		if len(later.certificates) != 3 {
			t.Fatal("resolution omitted historical certificate generation")
		}
		later.Close()
		if _, err := f.restarted().ResolveRenewal(t.Context(), id, f.roots); !errors.Is(err, ErrRenewalConflict) {
			t.Fatal("old resolution rolled back later activation", err)
		}
	}
}

func TestIdentityRenewalResolutionDurableNativeTransport(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "confirmed"}[confirmed], func(t *testing.T) { runDurableIdentityRenewalResolution(t, newMemoryBackend(t), confirmed) })
	}
}

func TestIdentityRenewalResolutionPublicationFailureRetainsDecision(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		for _, committed := range []bool{false, true} {
			t.Run(map[bool]string{false: "cancelled", true: "confirmed"}[confirmed]+map[bool]string{false: " before native commit", true: " after native commit"}[committed], func(t *testing.T) {
				b := newMemoryBackend(t)
				f := newRenewalFixture(t, b, "windows")
				id := f.uncertainRenewal(t, confirmed)
				b.failCreate, b.commitBeforeError = renewalRecord("resolved", 1), committed
				if identity, err := f.store.resolveRenewal(t.Context(), id, f.resolve); identity != nil || !errors.Is(err, ErrUnavailable) {
					t.Fatal("failed native resolution publication returned identity", err)
				}
				identity, err := f.restarted().Load()
				if committed {
					if err != nil || (identity.Response == f.original.Response) == confirmed {
						t.Fatal("lost native commit lost resolution", err)
					}
					identity.Close()
				} else if identity != nil || !errors.Is(err, ErrRenewalHandoff) {
					t.Fatal("unpublished resolution fell back", err)
				}
				b.failCreate, b.commitBeforeError = "", false
				identity, err = f.restarted().resolveRenewal(t.Context(), id, f.resolve)
				if err != nil || (identity.Response == f.original.Response) == confirmed {
					t.Fatal("resolution retry did not recover", err)
				}
				identity.Close()
			})
		}
	}
}

func TestIdentityRenewalResolutionRequiresExistingDecisionAndExactPublicOutcome(t *testing.T) {
	f := newRenewalFixture(t, newMemoryBackend(t), "windows")
	prepared, err := f.store.prepareRenewal(t.Context(), f.prepare)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.resolveRenewal(t.Context(), prepared.ID, func(context.Context, enrollment.RenewalResolution, enrollment.RenewalConfirmationTarget, enrollment.RenewalSource) (*enrollment.ResolvedIdentityRenewal, error) {
		t.Error("resolution without decision reached network")
		return nil, context.Canceled
	}); !errors.Is(err, ErrRenewalConflict) {
		t.Fatal("resolution created implicit confirmation decision", err)
	}
	_, err = f.store.confirmRenewal(t.Context(), prepared.ID, func(context.Context, enrollment.RenewalConfirmation, enrollment.RenewalConfirmationTarget) (*enrollment.ConfirmedIdentityRenewal, error) {
		return nil, context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, mode := range []string{"nil", "target", "source", "unknown outcome", "timestamp", "proof expiry", "transport cancellation"} {
		at := f.now
		identity, err := f.store.resolveRenewal(t.Context(), prepared.ID, func(ctx context.Context, q enrollment.RenewalResolution, target enrollment.RenewalConfirmationTarget, source enrollment.RenewalSource) (*enrollment.ResolvedIdentityRenewal, error) {
			if mode == "nil" {
				return nil, nil
			}
			if mode == "transport cancellation" {
				return nil, context.Canceled
			}
			r, err := f.resolve(ctx, q, target, source)
			if err != nil {
				return nil, err
			}
			switch mode {
			case "target":
				r.CertificateHash = renewalDigest([]byte("foreign candidate"))
			case "source":
				r.SourceCertificateHash = r.CertificateHash
			case "unknown outcome":
				r.Outcome = "not_found"
			case "timestamp":
				r.ResolvedAt = at.Add(2 * time.Minute)
			case "proof expiry":
				f.now = at.Add(enrollment.RenewalProofLifetime + time.Second)
			}
			return r, nil
		})
		f.now = at
		if identity != nil || err == nil {
			t.Fatal("invalid resolution returned credentials", mode)
		}
		if loaded, err := f.restarted().Load(); loaded != nil || !errors.Is(err, ErrRenewalHandoff) {
			t.Fatal("invalid resolution changed protected decision", mode, err)
		}
	}
	identity, err := f.store.resolveRenewal(t.Context(), prepared.ID, f.resolve)
	if err != nil {
		t.Fatal(err)
	}
	identity.Close()
}

func TestIdentityRenewalResolutionAndConfirmationRetainConsistentConcurrentEvidence(t *testing.T) {
	for range 4 {
		f := newRenewalFixture(t, newMemoryBackend(t), "windows")
		id := f.uncertainRenewal(t, false)
		var wg sync.WaitGroup
		var confirmErr, resolveErr error
		var confirmed, resolved *Identity
		wg.Go(func() { confirmed, confirmErr = f.store.confirmRenewal(t.Context(), id, f.confirm) })
		wg.Go(func() { resolved, resolveErr = f.store.resolveRenewal(t.Context(), id, f.resolve) })
		wg.Wait()
		if resolveErr != nil {
			t.Fatal("concurrent resolution failed", resolveErr)
		}
		if confirmErr != nil && !errors.Is(confirmErr, enrollment.ErrIdentityRenewalDenied) && !errors.Is(confirmErr, ErrRenewalConflict) {
			t.Fatal("unexpected confirmation race failure", confirmErr)
		}
		if confirmed != nil {
			if confirmed.Response != resolved.Response {
				t.Fatal("concurrent workflows selected different generations")
			}
			confirmed.Close()
		}
		loaded, err := f.restarted().Load()
		if err != nil || loaded.Response != resolved.Response {
			t.Fatal("concurrent evidence did not retain one current generation", err)
		}
		loaded.Close()
		resolved.Close()
	}
}

func TestIdentityRenewalResolvedHistoryRejectsCorruptionOrRemovedAnchors(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		b := newMemoryBackend(t)
		f := newRenewalFixture(t, b, "windows")
		id := f.uncertainRenewal(t, confirmed)
		identity, err := f.store.resolveRenewal(t.Context(), id, f.resolve)
		if err != nil {
			t.Fatal(err)
		}
		identity.Close()
		for _, stage := range []string{"candidate", "issued", "decision", "resolved"} {
			name := renewalRecord(stage, 1)
			original, err := b.Load(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, data := range [][]byte{nil, []byte("corrupt evidence"), append(bytes.Clone(original), 0)} {
				b.mu.Lock()
				if data == nil {
					delete(b.records, name)
				} else {
					b.records[name] = bytes.Clone(data)
				}
				b.mu.Unlock()
				loaded, err := f.restarted().Load()
				if loaded != nil || (!errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrRenewalHandoff)) {
					t.Fatal("corrupt resolution released credentials", stage, err)
				}
				b.mu.Lock()
				b.records[name] = bytes.Clone(original)
				b.mu.Unlock()
			}
			clear(original)
		}
		loaded, err := f.restarted().Load()
		if err != nil || !reflect.DeepEqual(loaded.Response, identity.Response) {
			t.Fatal("restored authentic evidence did not load", err)
		}
		loaded.Close()
	}
}
