package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

func TestIdentityRenewalCancellationResumesOnlyOriginalFileVaultJournal(t *testing.T) {
	f := newRenewalFixture(t, newMemoryBackend(t), "macos")
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
	context := enrollment.RotationContext{Binding: enrollment.RecoveryContext{Version: 1, Identity: journal.scope, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: uuid.NewString(), ExpiresAt: time.Now().Add(time.Minute).Unix()}, Ordinal: 1, EscrowID: uuid.NewString(), ReplyKey: hex.EncodeToString(console.PublicKey())}
	nonce := bytes.Repeat([]byte{8}, 32)
	task, err := enrollment.EncryptRotationTask(enrollment.RecoveryRecipient{Identity: journal.scope, ID: context.Binding.RecipientID, PublicKey: key.PublicKey()}, context, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if won, _, err := journal.BeginWithBootSession(*task, nonce, uuid.NewString()); err != nil || !won {
		t.Fatal(err)
	}
	receipt := journalResult(t, journal, f.original, context, nonce, "rotated")
	if err := journal.RecordResult(*receipt); err != nil {
		t.Fatal(err)
	}
	id := f.uncertainRenewal(t, false)
	if err := journal.RecordResult(*receipt); !errors.Is(err, ErrUnavailable) {
		t.Fatal("uncertain confirmation allowed old result publication", err)
	}
	identity, err := f.store.resolveRenewal(t.Context(), id, f.resolve)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	retained, err := f.store.LoadOrCreateRecipient(identity)
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	if !bytes.Equal(key.PublicKey(), retained.PublicKey()) {
		t.Fatal("cancellation replaced recipient key")
	}
	if err := journal.RecordResult(*receipt); err != nil {
		t.Fatal("authoritative cancellation did not restore original receipt publication", err)
	}
	entry, err := journal.Lookup(context)
	if err != nil || entry == nil || !reflect.DeepEqual(entry.Result, receipt) {
		t.Fatal("cancellation changed original encrypted receipt", err)
	}
}

func TestIdentityRenewalResolutionCannotUseExpiredOriginalCredentials(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel denied", true: "confirmed recovered"}[confirmed], func(t *testing.T) {
			f := newRenewalFixture(t, newMemoryBackend(t), "windows")
			id := f.uncertainRenewal(t, confirmed)
			f.now = f.original.Response.ExpiresAt
			identity, err := f.store.resolveRenewal(t.Context(), id, f.resolve)
			if confirmed {
				if err != nil || identity.Response == f.original.Response {
					t.Fatal("source expiry prevented confirmed recovery", err)
				}
				identity.Close()
			} else {
				if identity != nil || !errors.Is(err, enrollment.ErrIdentityRenewalDenied) {
					t.Fatal("resolution revived expired source", err)
				}
				if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrRenewalHandoff) {
					t.Fatal("source expiry abandoned uncertainty", err)
				}
			}
		})
	}
}

func TestIdentityRenewalCancellationReceivedAtSourceExpiryIsRetainedWithoutReturningKeys(t *testing.T) {
	b := newMemoryBackend(t)
	f := newRenewalFixture(t, b, "windows")
	id := f.uncertainRenewal(t, false)
	f.now = f.original.Response.ExpiresAt.Add(-time.Second)
	identity, err := f.store.resolveRenewal(t.Context(), id, func(ctx context.Context, q enrollment.RenewalResolution, target enrollment.RenewalConfirmationTarget, source enrollment.RenewalSource) (*enrollment.ResolvedIdentityRenewal, error) {
		result, err := f.resolve(ctx, q, target, source)
		f.now = f.original.Response.ExpiresAt
		return result, err
	})
	if identity != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("late cancellation reply returned expired credentials", err)
	}
	if data, err := b.Load(renewalRecord("resolved", 1)); err != nil || data == nil {
		t.Fatal("late reply discarded authentic cancellation", err)
	} else {
		clear(data)
	}
	if status, err := f.restarted().RenewalStatus(); err != nil || status != nil {
		t.Fatal("authentic cancellation was left uncertain", err)
	}
	for range 2 {
		if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("cancelled source loaded at its exact expiry", err)
		}
		if identity, err := f.restarted().resolveRenewal(t.Context(), id, f.resolve); identity != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("cancelled source retry extended expiry", err)
		}
	}
}

func TestIdentityRenewalResolutionCancelledContextAfterCommitRetainsHandoff(t *testing.T) {
	f := newRenewalFixture(t, newMemoryBackend(t), "windows")
	id := f.uncertainRenewal(t, false)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	identity, err := f.store.resolveRenewal(ctx, id, func(ctx context.Context, q enrollment.RenewalResolution, target enrollment.RenewalConfirmationTarget, source enrollment.RenewalSource) (*enrollment.ResolvedIdentityRenewal, error) {
		result, err := f.resolve(ctx, q, target, source)
		cancel()
		return result, err
	})
	if identity != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled caller received keys before durable outcome", err)
	}
	if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrRenewalHandoff) {
		t.Fatal("cancelled context allowed unjournalled fallback", err)
	}
	identity, err = f.restarted().resolveRenewal(t.Context(), id, f.resolve)
	if err != nil || identity.Response != f.original.Response {
		t.Fatal("committed cancellation could not be recovered", err)
	}
	identity.Close()
}

func TestIdentityRenewalLateResolutionCannotMoveHistoricalTransitionOrContradictActivation(t *testing.T) {
	b := newMemoryBackend(t)
	f := newRenewalFixture(t, b, "windows")
	id := f.uncertainRenewal(t, true)
	ready, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	var resolutionErr error
	released := false
	defer func() {
		if !released {
			close(release)
		}
		<-done
	}()
	go func() {
		identity, err := f.store.resolveRenewal(t.Context(), id, func(ctx context.Context, q enrollment.RenewalResolution, target enrollment.RenewalConfirmationTarget, source enrollment.RenewalSource) (*enrollment.ResolvedIdentityRenewal, error) {
			result, err := f.resolve(ctx, q, target, source)
			close(ready)
			<-release
			return result, err
		})
		if identity != nil {
			identity.Close()
			t.Error("late historical resolution returned credentials")
		}
		resolutionErr = err
		close(done)
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("resolution did not reach response boundary")
	}
	active, err := f.store.confirmRenewal(t.Context(), id, f.confirm)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	f.now = f.now.Add(2 * time.Minute)
	next, err := f.store.prepareRenewal(t.Context(), f.prepare)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.AbandonRenewal(next.ID); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * time.Minute)
	close(release)
	released = true
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("late resolution did not finish")
	}
	if !errors.Is(resolutionErr, ErrRenewalConflict) {
		t.Fatal("old resolution selected a later attempt", resolutionErr)
	}
	loaded, err := f.restarted().Load()
	if err != nil || loaded.Response != active.Response {
		t.Fatal("late duplicate evidence moved history past next attempt", err)
	}
	loaded.Close()
	decision, err := b.Load(renewalRecord("decision", 1))
	if err != nil {
		t.Fatal(err)
	}
	binding := sha256.Sum256(decision)
	clear(decision)
	original, err := b.Load(renewalRecord("resolved", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	for _, mode := range []string{"cancelled", "different confirmation time", "wrong proof domain"} {
		var record renewalResolution
		if err := decodeRenewalPublic(original, renewalResolvedMagic, binding, &record); err != nil {
			t.Fatal(err)
		}
		switch mode {
		case "cancelled":
			record.Resolved.Outcome = "cancelled"
		case "different confirmation time":
			record.Resolved.ResolvedAt = record.Resolved.ResolvedAt.Add(time.Microsecond)
		case "wrong proof domain":
			record.Request.Protocol = enrollment.RenewalConfirmationProtocol
		}
		changed, err := encodeRenewalPublic(renewalResolvedMagic, binding, record)
		if err != nil {
			t.Fatal(err)
		}
		b.mu.Lock()
		b.records[renewalRecord("resolved", 1)] = bytes.Clone(changed)
		b.mu.Unlock()
		clear(changed)
		if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("contradictory activation/resolution evidence selected keys", mode, err)
		}
		b.mu.Lock()
		b.records[renewalRecord("resolved", 1)] = bytes.Clone(original)
		b.mu.Unlock()
	}
}
