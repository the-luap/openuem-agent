package enrollmentstore

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
)

type resolveRenewalFunc func(context.Context, enrollment.RenewalResolution, enrollment.RenewalConfirmationTarget, enrollment.RenewalSource) (*enrollment.ResolvedIdentityRenewal, error)

// ResolveRenewal explicitly recovers activation or permanently cancels an
// unconfirmed candidate. It requires an already durable confirmation decision
// and quiescent credential/security users. Errors never grant old-key fallback.
// The actual resolution proof and verified outcome must reach immutable native
// storage before any selected identity is returned. No confirmation is fabricated.
func (s *Store) ResolveRenewal(ctx context.Context, requestID string, roots *x509.CertPool) (*Identity, error) {
	return s.resolveRenewal(ctx, requestID, func(ctx context.Context, request enrollment.RenewalResolution, target enrollment.RenewalConfirmationTarget, source enrollment.RenewalSource) (*enrollment.ResolvedIdentityRenewal, error) {
		client, err := enrollment.NewHTTPClient(target.Candidate.Origin, roots)
		if err != nil {
			return nil, err
		}
		defer client.CloseIdleConnections()
		return client.ResolveIdentityRenewal(ctx, request, target, source)
	})
}

func (s *Store) resolveRenewal(ctx context.Context, requestID string, exchange resolveRenewalFunc) (*Identity, error) {
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
	defer state.close()
	if state.pending == nil {
		return s.resolvedRenewalIdentity(state, requestID)
	}
	a := state.pending
	if a.request.RequestID != requestID || a.decision == nil || a.decision.Action != "confirm" || a.target == nil {
		return nil, ErrRenewalConflict
	}
	if _, err := enrollment.ValidateResponse(a.issuance.Prepared.Response, state.identity.Origin, &a.keys.Certificate.PublicKey, s.renewalTime()); err != nil {
		return nil, ErrUnavailable
	}
	request, err := enrollment.NewRenewalResolution(*a.target, a.keys, s.renewalTime())
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := exchange(ctx, *request, *a.target, state.source)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, enrollment.ErrInvalidResponse
	}
	received := s.renewalTime()
	record := renewalResolution{Request: *request, Resolved: *result, ReceivedAt: received}
	if !validRenewalResolution(record, a, state.source, received) {
		return nil, enrollment.ErrInvalidResponse
	}
	data, err := encodeRenewalPublic(renewalResolvedMagic, a.decisionDigest, record)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err = s.backend.Create(renewalRecord("resolved", a.ordinal), data); err != nil && !errors.Is(err, ErrExists) {
		return nil, ErrUnavailable
	}
	p2, saved, err := s.renewalState()
	if err != nil {
		return nil, err
	}
	defer p2.close()
	defer saved.close()
	return s.resolvedRenewalIdentity(saved, requestID)
}

func (s *Store) resolvedRenewalIdentity(state *renewalState, requestID string) (*Identity, error) {
	if state.pending != nil || state.lastRequest != requestID || (state.lastAction != "activated" && state.lastAction != "cancelled") {
		return nil, ErrRenewalConflict
	}
	if err := validateCurrentIdentity(state.identity, s.renewalTime()); err != nil {
		return nil, err
	}
	i := state.identity
	state.identity = nil
	return i, nil
}

func validateCurrentIdentity(i *Identity, now time.Time) error {
	certificate, err := enrollment.ValidateResponse(i.Response, i.Origin, &i.Keys.Certificate.PublicKey, now)
	if err != nil || !certificate.NotAfter.After(now) {
		return ErrUnavailable
	}
	return nil
}
