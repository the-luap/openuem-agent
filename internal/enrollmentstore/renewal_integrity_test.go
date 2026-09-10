package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func TestIdentityRenewalConcurrentPreparationRetainsOneCandidate(t *testing.T) {
	b := newMemoryBackend(t)
	f := newRenewalFixture(t, b, "windows")
	var wg sync.WaitGroup
	results := make(chan *enrollment.PreparedIdentityRenewal, 4)
	failures := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			prepared, err := f.restarted().prepareRenewal(t.Context(), f.prepare)
			if err != nil {
				failures <- err
				return
			}
			results <- prepared
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		// An incomplete read during another process's publication may require a
		// caller retry, but may never return a different or uncommitted candidate.
		if !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
	final, err := f.restarted().prepareRenewal(t.Context(), f.prepare)
	if err != nil {
		t.Fatal(err)
	}
	for prepared := range results {
		if *prepared != *final {
			t.Fatal("concurrent preparation selected different candidates")
		}
	}
	if f.preparations != 1 {
		t.Fatal("concurrent stores requested multiple issuances")
	}
	confirmErrors := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			identity, err := f.restarted().confirmRenewal(t.Context(), final.ID, f.confirm)
			if identity != nil {
				identity.Close()
			}
			confirmErrors <- err
		})
	}
	wg.Wait()
	close(confirmErrors)
	for err := range confirmErrors {
		if err != nil && !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
	active, err := f.restarted().confirmRenewal(t.Context(), final.ID, f.confirm)
	if err != nil {
		t.Fatal(err)
	}
	active.Close()
	if f.confirmations != 1 {
		t.Fatal("concurrent stores activated more than one generation")
	}
}

func TestIdentityRenewalConfirmationAndAbandonmentHaveOneDurableWinner(t *testing.T) {
	for range 4 {
		b := newMemoryBackend(t)
		f := newRenewalFixture(t, b, "windows")
		prepared, err := f.store.prepareRenewal(t.Context(), f.prepare)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		results := make(chan error, 2)
		wg.Go(func() {
			active, err := f.restarted().confirmRenewal(t.Context(), prepared.ID, f.confirm)
			if active != nil {
				active.Close()
			}
			results <- err
		})
		wg.Go(func() { results <- f.restarted().AbandonRenewal(prepared.ID) })
		wg.Wait()
		close(results)
		wins := 0
		for err := range results {
			if err == nil {
				wins++
			} else if !errors.Is(err, ErrRenewalHandoff) && !errors.Is(err, ErrRenewalConflict) && !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
		}
		if wins != 1 {
			t.Fatal("confirm and abandon did not have exactly one winner", wins)
		}
		data, err := b.Load(renewalRecord("candidate", 1))
		if err != nil {
			t.Fatal(err)
		}
		candidateDigest := renewalDigest(data)
		clear(data)
		data, err = b.Load(renewalRecord("decision", 1))
		if err != nil {
			t.Fatal(err)
		}
		fields, err := decodeFields(data, renewalDecisionMagic, 2)
		if err != nil || hex.EncodeToString(fields[0]) != candidateDigest {
			t.Fatal("decision lost candidate binding", err)
		}
		var decision renewalDecision
		if decodeCanonicalJSON(fields[1], &decision) != nil {
			t.Fatal("invalid persisted decision")
		}
		clear(data)
		if decision.Action == "confirm" {
			if f.confirmations != 1 {
				t.Fatal("winning confirmation did not activate")
			}
			if err := f.restarted().AbandonRenewal(prepared.ID); !errors.Is(err, ErrRenewalConflict) {
				t.Fatal("activated attempt could be abandoned", err)
			}
		} else {
			if f.confirmations != 0 {
				t.Fatal("abandoned candidate reached confirmation transport")
			}
			if err := f.restarted().AbandonRenewal(prepared.ID); err != nil {
				t.Fatal("exact abandonment retry failed", err)
			}
			if _, err := f.restarted().confirmRenewal(t.Context(), prepared.ID, f.confirm); !errors.Is(err, ErrRenewalConflict) {
				t.Fatal("abandoned candidate was reactivated", err)
			}
		}
	}
}

func TestIdentityRenewalInvalidResponsesCannotPublishIssuanceOrActivation(t *testing.T) {
	b := newMemoryBackend(t)
	f := newRenewalFixture(t, b, "windows")
	for _, mutate := range []func(*enrollment.PreparedIdentityRenewal){
		func(r *enrollment.PreparedIdentityRenewal) { r.ID = uuid.NewString() },
		func(r *enrollment.PreparedIdentityRenewal) { r.Response.SiteID++ },
		func(r *enrollment.PreparedIdentityRenewal) { r.Response.Certificate = f.original.Response.Certificate },
		func(r *enrollment.PreparedIdentityRenewal) { r.ExpiresAt = f.now.Add(8 * 24 * time.Hour) },
	} {
		_, err := f.store.prepareRenewal(t.Context(), func(ctx context.Context, request enrollment.RenewalRequest, source enrollment.RenewalSource) (*enrollment.PreparedIdentityRenewal, error) {
			response, err := f.prepare(ctx, request, source)
			if err == nil {
				mutate(response)
			}
			return response, err
		})
		if !errors.Is(err, enrollment.ErrInvalidResponse) {
			t.Fatal("unbound response was accepted", err)
		}
		if data, err := b.Load(renewalRecord("issued", 1)); !errors.Is(err, ErrMissing) {
			clear(data)
			t.Fatal("invalid response persisted issuance")
		}
	}
	prepared, err := f.store.prepareRenewal(t.Context(), f.prepare)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*enrollment.ConfirmedIdentityRenewal){
		func(r *enrollment.ConfirmedIdentityRenewal) { r.ID = uuid.NewString() },
		func(r *enrollment.ConfirmedIdentityRenewal) { r.DeviceID = uuid.NewString() },
		func(r *enrollment.ConfirmedIdentityRenewal) { r.CertificateHash = prepared.SourceCertificateHash },
		func(r *enrollment.ConfirmedIdentityRenewal) { r.ConfirmedAt = f.now.Add(2 * time.Minute) },
	} {
		_, err := f.store.confirmRenewal(t.Context(), prepared.ID, func(ctx context.Context, request enrollment.RenewalConfirmation, target enrollment.RenewalConfirmationTarget) (*enrollment.ConfirmedIdentityRenewal, error) {
			response, err := f.confirm(ctx, request, target)
			if err == nil {
				mutate(response)
			}
			return response, err
		})
		if !errors.Is(err, enrollment.ErrInvalidResponse) {
			t.Fatal("unbound confirmation was accepted", err)
		}
		if data, err := b.Load(renewalRecord("activated", 1)); !errors.Is(err, ErrMissing) {
			clear(data)
			t.Fatal("invalid response persisted activation")
		}
		if _, err := f.store.Load(); !errors.Is(err, ErrRenewalHandoff) {
			t.Fatal("invalid response permitted old-key fallback", err)
		}
	}
	active, err := f.restarted().confirmRenewal(t.Context(), prepared.ID, f.confirm)
	if err != nil {
		t.Fatal(err)
	}
	active.Close()
}

func TestIdentityRenewalCorruptMissingAndOrphanHistoryNeverFallsBack(t *testing.T) {
	b := newMemoryBackend(t)
	f := newRenewalFixture(t, b, "windows")
	for range 2 {
		prepared, err := f.store.prepareRenewal(t.Context(), f.prepare)
		if err != nil {
			t.Fatal(err)
		}
		active, err := f.store.confirmRenewal(t.Context(), prepared.ID, f.confirm)
		if err != nil {
			t.Fatal(err)
		}
		active.Close()
	}
	for ordinal := 1; ordinal <= 2; ordinal++ {
		for _, stage := range renewalStages[:4] {
			name := renewalRecord(stage, ordinal)
			original, err := b.Load(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, mutation := range [][]byte{nil, []byte("corrupt retained renewal"), append(bytes.Clone(original), 0)} {
				b.mu.Lock()
				if mutation == nil {
					delete(b.records, name)
				} else {
					b.records[name] = bytes.Clone(mutation)
				}
				b.mu.Unlock()
				identity, err := f.restarted().Load()
				if identity != nil {
					identity.Close()
				}
				expected := ErrUnavailable
				if mutation == nil && ordinal == 2 && stage == "activated" {
					expected = ErrRenewalHandoff
				}
				if !errors.Is(err, expected) {
					t.Fatal("corrupt generation returned older keys", stage, ordinal, err)
				}
				b.mu.Lock()
				b.records[name] = bytes.Clone(original)
				b.mu.Unlock()
			}
			clear(original)
		}
	}
	for _, anchor := range []string{pendingRecord, identityRecord} {
		original, _ := b.Load(anchor)
		b.mu.Lock()
		delete(b.records, anchor)
		b.mu.Unlock()
		if _, err := f.restarted().Load(); !errors.Is(err, ErrUnavailable) {
			t.Fatal("renewal history recreated a missing installation anchor", err)
		}
		b.mu.Lock()
		b.records[anchor] = bytes.Clone(original)
		b.mu.Unlock()
		clear(original)
	}
	if err := b.Create(renewalRecord("decision", MaxIdentityRenewalAttempts), []byte("orphan confirmation decision")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.restarted().Load(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("later orphaned decision was ignored", err)
	}
}

func TestIdentityRenewalExplicitAbandonmentRetainsServerPendingBoundary(t *testing.T) {
	f := newRenewalFixture(t, newMemoryBackend(t), "windows")
	prepared, err := f.store.prepareRenewal(t.Context(), func(ctx context.Context, request enrollment.RenewalRequest, source enrollment.RenewalSource) (*enrollment.PreparedIdentityRenewal, error) {
		response, err := f.prepare(ctx, request, source)
		if err == nil {
			response.ExpiresAt = f.now.Add(time.Minute)
			f.prepared[response.ID].ExpiresAt = response.ExpiresAt
		}
		return response, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.AbandonRenewal(prepared.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.confirmRenewal(t.Context(), prepared.ID, f.confirm); !errors.Is(err, ErrRenewalConflict) {
		t.Fatal("abandoned candidate could confirm", err)
	}
	if _, err := f.store.prepareRenewal(t.Context(), f.prepare); !errors.Is(err, enrollment.ErrIdentityRenewalPending) {
		t.Fatal("local abandonment cancelled the server's reservation", err)
	}
	status, err := f.store.RenewalStatus()
	if err != nil || status == nil || status.RequestID == prepared.ID || status.Stage != "candidate" {
		t.Fatal("replacement candidate did not remain durable", err)
	}
	f.now = f.now.Add(2 * time.Minute)
	next, err := f.restarted().prepareRenewal(t.Context(), f.prepare)
	if err != nil || next.ID != status.RequestID {
		t.Fatal("expired server reservation lost the next candidate", err)
	}
	active, err := f.store.confirmRenewal(t.Context(), next.ID, f.confirm)
	if err != nil {
		t.Fatal(err)
	}
	active.Close()
	if f.preparations != 2 || f.confirmations != 1 {
		t.Fatal("abandoned generation was activated or history was reused")
	}
}

func TestIdentityRenewalExhaustedHistoryCannotGenerateAnotherCandidate(t *testing.T) {
	b := newMemoryBackend(t)
	f := newRenewalFixture(t, b, "windows")
	p, err := f.store.loadPending()
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	for ordinal := 1; ordinal <= MaxIdentityRenewalAttempts; ordinal++ {
		// The protocol supports same-key candidates. Reuse these owned fixture
		// keys only to construct a complete valid bounded abandoned history.
		request, err := enrollment.NewRenewalRequest(f.source, f.original.Keys, f.original.Keys, uuid.NewString(), f.now)
		if err != nil {
			t.Fatal(err)
		}
		data, err := encodeRenewalCandidate(p, f.source, *request, f.original.Keys, ordinal)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if err := b.Create(renewalRecord("candidate", ordinal), data); err != nil {
			t.Fatal(err)
		}
		clear(data)
		data, err = encodeRenewalPublic(renewalDecisionMagic, digest, renewalDecision{Action: "abandon", DecidedAt: f.now})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Create(renewalRecord("decision", ordinal), data); err != nil {
			t.Fatal(err)
		}
		clear(data)
	}
	called := false
	if _, err := f.store.prepareRenewal(t.Context(), func(context.Context, enrollment.RenewalRequest, enrollment.RenewalSource) (*enrollment.PreparedIdentityRenewal, error) {
		called = true
		return nil, nil
	}); !errors.Is(err, ErrUnavailable) || called {
		t.Fatal("exhausted history admitted another attempt", err)
	}
	identity, err := f.store.Load()
	if err != nil || identity.Response != f.original.Response {
		t.Fatal("history exhaustion changed active identity", err)
	}
	identity.Close()
	if len(b.records) != 2+2*MaxIdentityRenewalAttempts {
		t.Fatal("exhausted history created another record")
	}
}

func TestIdentityRenewalFragmentsPreventNewEnrollmentWithoutAnyOtherAnchor(t *testing.T) {
	pending := restorePendingFixture(t)
	for _, stage := range renewalStages {
		t.Run(stage, func(t *testing.T) {
			runRetainedSecurityPreventsEnrollment(t, newMemoryBackend(t), renewalRecord(stage, MaxIdentityRenewalAttempts), pending)
		})
	}
}

func TestIdentityRenewalCancelledCommittedConfirmationRetainsCandidate(t *testing.T) {
	f := newRenewalFixture(t, newMemoryBackend(t), "windows")
	prepared, err := f.store.prepareRenewal(t.Context(), f.prepare)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, err = f.store.confirmRenewal(ctx, prepared.ID, func(ctx context.Context, request enrollment.RenewalConfirmation, target enrollment.RenewalConfirmationTarget) (*enrollment.ConfirmedIdentityRenewal, error) {
		response, err := f.confirm(ctx, request, target)
		cancel()
		return response, err
	})
	if !errors.Is(err, context.Canceled) || f.confirmations != 1 {
		t.Fatal("cancellation did not occur after server commit", err)
	}
	if _, err := f.store.Load(); !errors.Is(err, ErrRenewalHandoff) {
		t.Fatal("cancelled confirmation allowed original keys", err)
	}
	active, err := f.restarted().confirmRenewal(t.Context(), prepared.ID, f.confirm)
	if err != nil {
		t.Fatal(err)
	}
	active.Close()
}

func TestIdentityRenewalPreservesFileVaultRecipientAndHistoricalReceipts(t *testing.T) {
	for _, resolve := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmation", true: "confirmed resolution"}[resolve], func(t *testing.T) {
			b := newMemoryBackend(t)
			f := newRenewalFixture(t, b, "macos")
			key, err := f.store.LoadOrCreateRecipient(f.original)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Close()
			console, err := enrollment.NewRecoveryRecipientKey()
			if err != nil {
				t.Fatal(err)
			}
			defer console.Close()
			journal, err := f.store.OpenRotationJournal(f.original)
			if err != nil {
				t.Fatal(err)
			}
			makeTask := func(j *RotationJournal, ordinal int) (*enrollment.RotationTask, []byte) {
				context := enrollment.RotationContext{Binding: enrollment.RecoveryContext{Version: 1, Identity: j.scope, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: uuid.NewString(), ExpiresAt: time.Now().Add(time.Minute).Unix()}, Ordinal: ordinal, EscrowID: uuid.NewString(), ReplyKey: hex.EncodeToString(console.PublicKey())}
				nonce := bytes.Repeat([]byte{8}, 32)
				task, err := enrollment.EncryptRotationTask(enrollment.RecoveryRecipient{Identity: j.scope, ID: context.Binding.RecipientID, PublicKey: key.PublicKey()}, context, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), nonce, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				return task, nonce
			}
			task, nonce := makeTask(journal, 1)
			if won, _, err := journal.BeginWithBootSession(*task, nonce, uuid.NewString()); err != nil || !won {
				t.Fatal(err)
			}
			receipt := journalResult(t, journal, f.original, task.Context, nonce, "rotated")
			if err := journal.RecordResult(*receipt); err != nil {
				t.Fatal(err)
			}
			before := make(map[string][]byte)
			for _, name := range []string{pendingRecord, identityRecord, recipientRecord, rotationAnchorRecord, rotationRecord(false, 1), rotationRecord(true, 1)} {
				data, err := b.Load(name)
				if err != nil {
					t.Fatal(err)
				}
				before[name] = data
				defer clear(data)
			}
			prepared, err := f.store.prepareRenewal(t.Context(), f.prepare)
			if err != nil {
				t.Fatal(err)
			}
			oldTask, oldNonce := makeTask(journal, 2)
			active, err := f.store.confirmRenewal(t.Context(), prepared.ID, func(ctx context.Context, request enrollment.RenewalConfirmation, target enrollment.RenewalConfirmationTarget) (*enrollment.ConfirmedIdentityRenewal, error) {
				if won, _, err := journal.BeginWithBootSession(*oldTask, oldNonce, uuid.NewString()); won || !errors.Is(err, ErrUnavailable) {
					t.Fatal("confirmation intent admitted old-generation mutation", err)
				}
				result, err := f.confirm(ctx, request, target)
				if resolve && err == nil {
					return nil, enrollment.ErrEnrollmentBusy
				}
				return result, err
			})
			if resolve {
				if !errors.Is(err, enrollment.ErrEnrollmentBusy) {
					t.Fatal("fixture lost confirmation was not retained", err)
				}
				active, err = f.store.resolveRenewal(t.Context(), prepared.ID, f.resolve)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer active.Close()
			if err := journal.RecordResult(*receipt); !errors.Is(err, ErrUnavailable) {
				t.Fatal("retired journal published a result", err)
			}
			retained, err := f.store.LoadOrCreateRecipient(active)
			if err != nil {
				t.Fatal(err)
			}
			defer retained.Close()
			if !bytes.Equal(retained.PublicKey(), key.PublicKey()) {
				t.Fatal("renewal replaced the protected recipient key")
			}
			currentJournal, err := f.store.OpenRotationJournal(active)
			if err != nil {
				t.Fatal(err)
			}
			conflict, conflictNonce := makeTask(currentJournal, 1)
			if won, _, err := currentJournal.BeginWithBootSession(*conflict, conflictNonce, uuid.NewString()); won || !errors.Is(err, ErrUnavailable) {
				t.Fatal("renewal reset a permanent rotation ordinal", err)
			}
			next, nextNonce := makeTask(currentJournal, 2)
			if won, _, err := currentJournal.BeginWithBootSession(*next, nextNonce, uuid.NewString()); err != nil || !won {
				t.Fatal("current generation could not admit the next ordinal", err)
			}
			f.now = f.original.Response.ExpiresAt.Add(time.Hour)
			loaded, err := f.restarted().Load()
			if err != nil {
				t.Fatal("expired anchor prevented current identity load", err)
			}
			defer loaded.Close()
			currentJournal, err = f.restarted().OpenRotationJournal(loaded)
			if err != nil {
				t.Fatal(err)
			}
			entry, err := currentJournal.Lookup(task.Context)
			if err != nil || entry == nil || !reflect.DeepEqual(entry.Result, receipt) {
				t.Fatal("retired certificate could not verify its exact historical receipt", err)
			}
			if won, _, err := currentJournal.Begin(*task, nonce); won || !errors.Is(err, ErrUnavailable) {
				t.Fatal("historical read authorized old-generation execution", err)
			}
			for name, original := range before {
				after, err := b.Load(name)
				if err != nil || !bytes.Equal(after, original) {
					t.Fatal("renewal changed FileVault replay evidence", name, err)
				}
				clear(after)
			}
		})
	}
}
