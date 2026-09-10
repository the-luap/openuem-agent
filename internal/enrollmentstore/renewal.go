package enrollmentstore

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

var (
	ErrRenewalHandoff  = errors.New("individual identity handoff requires candidate confirmation recovery")
	ErrRenewalConflict = errors.New("individual identity renewal does not match the retained attempt")
)

// RenewalStatus contains public local progress only. Confirmation intent means
// the server may already have activated the candidate, even after transport cancellation,
// an error response or preparation expiry. Never restore old keys in that state.
type RenewalStatus struct {
	RequestID string
	Stage     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (s *Store) RenewalStatus() (*RenewalStatus, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, state, err := s.renewalState()
	if err != nil {
		return nil, err
	}
	defer p.close()
	defer state.close()
	return renewalStatus(state), nil
}

func renewalStatus(state *renewalState) *RenewalStatus {
	a := state.pending
	if a == nil {
		return nil
	}
	status := &RenewalStatus{RequestID: a.request.RequestID, Stage: "candidate", CreatedAt: time.Unix(a.request.IssuedAt, 0)}
	if a.issuance != nil {
		status.Stage, status.ExpiresAt = "prepared", a.issuance.Prepared.ExpiresAt
	}
	if a.decision != nil {
		status.Stage = "confirming"
	}
	return status
}

// RenewalSchedule exposes authenticated public timing, including during a
// confirmation quarantine. It never grants permission to use expired/source keys.
// Cancellation cooldown survives restarts because it derives from retained
// resolution evidence, without mutable scheduler state or another secret record.
type RenewalSchedule struct {
	Pending    *RenewalStatus
	ExpiresAt  time.Time
	RetryAfter time.Time
}

func (s *Store) RenewalSchedule() (*RenewalSchedule, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, state, err := s.renewalState()
	if err != nil {
		return nil, err
	}
	defer p.close()
	defer state.close()
	result := &RenewalSchedule{Pending: renewalStatus(state), ExpiresAt: state.identity.Response.ExpiresAt}
	if state.pending == nil && state.lastAction == "cancelled" {
		delay := min(7*24*time.Hour, max(time.Hour, result.ExpiresAt.Sub(state.transition)/2))
		result.RetryAfter = state.transition.Add(delay)
	}
	return result, nil
}

func (s *Store) renewalState() (*pending, *renewalState, error) {
	if s.backend == nil {
		return nil, nil, ErrUnavailable
	}
	p, err := s.loadPending()
	if err != nil {
		return nil, nil, err
	}
	state, err := s.loadRenewalState(p)
	if err != nil {
		p.close()
		return nil, nil, err
	}
	return p, state, nil
}

type prepareRenewalFunc func(context.Context, enrollment.RenewalRequest, enrollment.RenewalSource) (*enrollment.PreparedIdentityRenewal, error)
type confirmRenewalFunc func(context.Context, enrollment.RenewalConfirmation, enrollment.RenewalConfirmationTarget) (*enrollment.ConfirmedIdentityRenewal, error)

// PrepareRenewal creates both candidate private keys and a request ID in native
// immutable storage before the first HTTPS request. Retries reuse that exact
// candidate. It does not switch the identity, consume another invitation, trust a
// response-provided HTTPS CA, or automatically abandon any previous attempt.
func (s *Store) PrepareRenewal(ctx context.Context, roots *x509.CertPool) (*enrollment.PreparedIdentityRenewal, error) {
	return s.prepareRenewal(ctx, func(ctx context.Context, request enrollment.RenewalRequest, source enrollment.RenewalSource) (*enrollment.PreparedIdentityRenewal, error) {
		client, err := enrollment.NewHTTPClient(source.Origin, roots)
		if err != nil {
			return nil, err
		}
		defer client.CloseIdleConnections()
		return client.PrepareIdentityRenewal(ctx, request, source)
	})
}

func (s *Store) prepareRenewal(ctx context.Context, exchange prepareRenewalFunc) (*enrollment.PreparedIdentityRenewal, error) {
	if s == nil || ctx == nil || exchange == nil {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, state, err := s.renewalState()
	if err != nil {
		return nil, err
	}
	defer p.close()
	defer func() { state.close() }()
	now := s.renewalTime()
	if state.pending != nil && state.pending.decision != nil {
		return nil, ErrRenewalHandoff
	}
	i := state.identity
	cert, err := enrollment.ValidateResponse(i.Response, i.Origin, &i.Keys.Certificate.PublicKey, now)
	if err != nil {
		return nil, ErrUnavailable
	}
	if state.pending == nil {
		if cert.NotAfter.After(now.Add(30 * 24 * time.Hour)) {
			return nil, enrollment.ErrIdentityRenewalNotDue
		}
		if !cert.NotAfter.After(now.Add(5*time.Minute)) || state.next > MaxIdentityRenewalAttempts {
			return nil, ErrUnavailable
		}
		keys, err := enrollment.GenerateKeys()
		if err != nil {
			return nil, ErrUnavailable
		}
		request, err := enrollment.NewRenewalRequest(state.source, i.Keys, keys, uuid.NewString(), s.renewalTime())
		if err != nil {
			releaseKeys(keys)
			return nil, err
		}
		if !renewalTimeOrdered(time.Unix(request.IssuedAt, 0), state.transition, s.renewalTime()) {
			releaseKeys(keys)
			return nil, ErrUnavailable
		}
		data, err := encodeRenewalCandidate(p, state.source, *request, keys, state.next)
		releaseKeys(keys)
		if err != nil {
			return nil, err
		}
		if err = ctx.Err(); err == nil {
			err = s.backend.Create(renewalRecord("candidate", state.next), data)
		}
		clear(data)
		if err != nil && !errors.Is(err, ErrExists) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrUnavailable
		}
		// Reload from a fresh pending anchor: loadRenewalState transfers key
		// ownership, and only the exclusive durable winner may reach the network.
		p2, next, err := s.renewalState()
		if err != nil {
			return nil, err
		}
		p2.close()
		state.close()
		state = next
	}
	a := state.pending
	if a == nil {
		return nil, ErrRenewalConflict
	}
	if a.decision != nil {
		return nil, ErrRenewalHandoff
	}
	if a.issuance != nil {
		if !a.issuance.Prepared.ExpiresAt.After(s.renewalTime()) {
			return nil, enrollment.ErrIdentityRenewalDenied
		}
		prepared := a.issuance.Prepared
		return &prepared, nil
	}
	request, err := enrollment.NewRenewalRequest(state.source, state.identity.Keys, a.keys, a.request.RequestID, s.renewalTime())
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prepared, err := exchange(ctx, *request, state.source)
	if err != nil {
		return nil, err
	}
	received := s.renewalTime()
	if prepared == nil {
		return nil, enrollment.ErrInvalidResponse
	}
	if _, err := enrollment.ValidatePreparedIdentityRenewal(*prepared, *request, state.source, received); err != nil {
		return nil, err
	}
	if !renewalTimeOrdered(received, time.Unix(a.request.IssuedAt, 0), received) {
		return nil, ErrUnavailable
	}
	data, err := encodeRenewalPublic(renewalIssuedMagic, a.digest, renewalIssuance{Request: *request, Prepared: *prepared, ReceivedAt: received})
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err = s.backend.Create(renewalRecord("issued", a.ordinal), data); err != nil && !errors.Is(err, ErrExists) {
		return nil, ErrUnavailable
	}
	p2, saved, err := s.renewalState()
	if err != nil {
		return nil, err
	}
	defer p2.close()
	defer saved.close()
	if saved.pending == nil || saved.pending.request.RequestID != a.request.RequestID {
		return nil, ErrRenewalConflict
	}
	if saved.pending.decision != nil {
		return nil, ErrRenewalHandoff
	}
	if saved.pending.issuance == nil || !saved.pending.issuance.Prepared.ExpiresAt.After(s.renewalTime()) {
		return nil, ErrUnavailable
	}
	result := saved.pending.issuance.Prepared
	return &result, nil
}

// ConfirmRenewal requires the caller to stop users of the old credentials and
// security-task execution before calling. It records an exclusive decision before
// any confirmation I/O. All failed/ambiguous attempts retain that decision and both
// generations. Load then refuses old-key fallback until this exact candidate's
// confirmation or authoritative resolution is durably retained.
func (s *Store) ConfirmRenewal(ctx context.Context, requestID string, roots *x509.CertPool) (*Identity, error) {
	return s.confirmRenewal(ctx, requestID, func(ctx context.Context, request enrollment.RenewalConfirmation, target enrollment.RenewalConfirmationTarget) (*enrollment.ConfirmedIdentityRenewal, error) {
		client, err := enrollment.NewHTTPClient(target.Candidate.Origin, roots)
		if err != nil {
			return nil, err
		}
		defer client.CloseIdleConnections()
		return client.ConfirmIdentityRenewal(ctx, request, target)
	})
}

func (s *Store) confirmRenewal(ctx context.Context, requestID string, exchange confirmRenewalFunc) (*Identity, error) {
	if s == nil || ctx == nil || exchange == nil || !enrollment.ValidDeviceID(requestID) {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, state, err := s.renewalState()
	if err != nil {
		return nil, err
	}
	defer p.close()
	defer func() { state.close() }()
	if state.pending == nil {
		return s.confirmedRenewalIdentity(state, requestID)
	}
	a := state.pending
	if a.request.RequestID != requestID || a.issuance == nil {
		return nil, ErrRenewalConflict
	}
	if _, err := enrollment.ValidateResponse(a.issuance.Prepared.Response, state.identity.Origin, &a.keys.Certificate.PublicKey, s.renewalTime()); err != nil {
		return nil, ErrUnavailable
	}
	if a.decision == nil {
		now := s.renewalTime()
		if !a.issuance.Prepared.ExpiresAt.After(now) {
			return nil, enrollment.ErrIdentityRenewalDenied
		}
		if !renewalTimeOrdered(now, a.issuance.ReceivedAt, now) {
			return nil, ErrUnavailable
		}
		decision := renewalDecision{Action: "confirm", IssuanceDigest: hex.EncodeToString(a.issuanceDigest[:]), DecidedAt: now}
		data, err := encodeRenewalPublic(renewalDecisionMagic, a.digest, decision)
		if err != nil {
			return nil, err
		}
		if err = ctx.Err(); err == nil {
			err = s.backend.Create(renewalRecord("decision", a.ordinal), data)
		}
		clear(data)
		if err != nil && !errors.Is(err, ErrExists) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrUnavailable
		}
		p2, next, err := s.renewalState()
		if err != nil {
			return nil, err
		}
		p2.close()
		state.close()
		state = next
		if state.pending == nil {
			return s.confirmedRenewalIdentity(state, requestID)
		}
		a = state.pending
	}
	if a.request.RequestID != requestID || a.decision == nil || a.decision.Action != "confirm" || a.target == nil {
		return nil, ErrRenewalConflict
	}
	if _, err := enrollment.ValidateResponse(a.issuance.Prepared.Response, state.identity.Origin, &a.keys.Certificate.PublicKey, s.renewalTime()); err != nil {
		return nil, ErrUnavailable
	}
	request, err := enrollment.NewRenewalConfirmation(*a.target, a.keys, s.renewalTime())
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	confirmed, err := exchange(ctx, *request, *a.target)
	if err != nil {
		return nil, err
	}
	received := s.renewalTime()
	if confirmed == nil {
		return nil, enrollment.ErrInvalidResponse
	}
	if err := enrollment.ValidateConfirmedIdentityRenewal(*confirmed, *request, *a.target, received); err != nil {
		return nil, err
	}
	if !confirmed.ConfirmedAt.Before(a.issuance.Prepared.ExpiresAt) || !renewalTimeOrdered(confirmed.ConfirmedAt, a.decision.DecidedAt, received) || !renewalTimeOrdered(received, a.decision.DecidedAt, received) {
		return nil, enrollment.ErrInvalidResponse
	}
	data, err := encodeRenewalPublic(renewalActivatedMagic, a.decisionDigest, renewalActivation{Request: *request, Confirmed: *confirmed, ReceivedAt: received})
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err = s.backend.Create(renewalRecord("activated", a.ordinal), data); err != nil && !errors.Is(err, ErrExists) {
		return nil, ErrUnavailable
	}
	p2, saved, err := s.renewalState()
	if err != nil {
		return nil, err
	}
	defer p2.close()
	defer saved.close()
	return s.confirmedRenewalIdentity(saved, requestID)
}

func (s *Store) confirmedRenewalIdentity(state *renewalState, requestID string) (*Identity, error) {
	if state.pending != nil || state.lastRequest != requestID || state.lastAction != "activated" {
		return nil, ErrRenewalConflict
	}
	i := state.identity
	if err := validateCurrentIdentity(i, s.renewalTime()); err != nil {
		return nil, ErrUnavailable
	}
	state.identity = nil
	return i, nil
}

// AbandonRenewal is an explicit local decision for a candidate whose confirmation
// has never been authorized. It cannot win after confirmation intent, and never
// deletes keys or history. A server-side preparation can remain reserved until
// expiry; a later preparation must still satisfy the registry's pending guard.
func (s *Store) AbandonRenewal(requestID string) error {
	if s == nil || !enrollment.ValidDeviceID(requestID) {
		return ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, state, err := s.renewalState()
	if err != nil {
		return err
	}
	defer p.close()
	defer state.close()
	if state.pending == nil {
		if state.lastRequest == requestID && state.lastAction == "abandon" {
			return nil
		}
		return ErrRenewalConflict
	}
	a := state.pending
	if a.request.RequestID != requestID {
		return ErrRenewalConflict
	}
	if a.decision != nil {
		return ErrRenewalHandoff
	}
	now := s.renewalTime()
	if !renewalTimeOrdered(now, time.Unix(a.request.IssuedAt, 0), now) {
		return ErrUnavailable
	}
	data, err := encodeRenewalPublic(renewalDecisionMagic, a.digest, renewalDecision{Action: "abandon", DecidedAt: now})
	if err != nil {
		return err
	}
	defer clear(data)
	if err = s.backend.Create(renewalRecord("decision", a.ordinal), data); err != nil && !errors.Is(err, ErrExists) {
		return ErrUnavailable
	}
	p2, saved, err := s.renewalState()
	if err != nil {
		return err
	}
	defer p2.close()
	defer saved.close()
	if saved.pending != nil && saved.pending.request.RequestID == requestID && saved.pending.decision != nil {
		return ErrRenewalHandoff
	}
	if saved.lastRequest != requestID || saved.lastAction != "abandon" {
		return ErrRenewalConflict
	}
	return nil
}
