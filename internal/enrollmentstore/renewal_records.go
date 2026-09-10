package enrollmentstore

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/open-uem/nats/enrollment"
)

// MaxIdentityRenewalAttempts bounds permanent local history, including abandoned
// attempts. No slot is deleted or reused; the registry has the same history cap.
const MaxIdentityRenewalAttempts = 128

var renewalStages = [...]string{"candidate", "issued", "decision", "activated"}

const (
	renewalCandidateMagic = "openuem/enrollment/renewal/candidate/v1\x00"
	renewalIssuedMagic    = "openuem/enrollment/renewal/issued/v1\x00"
	renewalDecisionMagic  = "openuem/enrollment/renewal/decision/v1\x00"
	renewalActivatedMagic = "openuem/enrollment/renewal/activated/v1\x00"
)

// These types are private native-storage codecs, never network or log values.
type renewalIssuance struct {
	Request    enrollment.RenewalRequest          `json:"request"`
	Prepared   enrollment.PreparedIdentityRenewal `json:"prepared"`
	ReceivedAt time.Time                          `json:"received_at"`
}

type renewalDecision struct {
	Action         string    `json:"action"`
	IssuanceDigest string    `json:"issuance_digest"`
	DecidedAt      time.Time `json:"decided_at"`
}

type renewalActivation struct {
	Request    enrollment.RenewalConfirmation      `json:"request"`
	Confirmed  enrollment.ConfirmedIdentityRenewal `json:"confirmed"`
	ReceivedAt time.Time                           `json:"received_at"`
}

type renewalCertificate struct {
	certificate *x509.Certificate
	retiredAt   time.Time
}

type renewalAttempt struct {
	ordinal                                int
	keys                                   *enrollment.Keys
	request                                enrollment.RenewalRequest
	intent                                 string
	digest, issuanceDigest, decisionDigest [sha256.Size]byte
	issuance                               *renewalIssuance
	target                                 *enrollment.RenewalConfirmationTarget
	decision                               *renewalDecision
	activation                             *renewalActivation
}

func (*renewalAttempt) String() string               { return "[protected identity renewal attempt]" }
func (a *renewalAttempt) GoString() string           { return a.String() }
func (*renewalAttempt) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

func (a *renewalAttempt) close() {
	if a != nil {
		releaseKeys(a.keys)
		a.keys = nil
	}
}

type renewalState struct {
	identity                *Identity
	source                  enrollment.RenewalSource
	pending                 *renewalAttempt
	next                    int
	lastRequest, lastAction string
	transition              time.Time
}

func (*renewalState) String() string               { return "[protected identity renewal state]" }
func (r *renewalState) GoString() string           { return r.String() }
func (*renewalState) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

func (r *renewalState) close() {
	if r == nil {
		return
	}
	if r.identity != nil {
		r.identity.Close()
		r.identity = nil
	}
	r.pending.close()
	r.pending = nil
}

func (s *Store) renewalTime() time.Time {
	if s.renewalClock != nil {
		return s.renewalClock().UTC()
	}
	return time.Now().UTC()
}

func renewalRecord(stage string, ordinal int) string {
	return fmt.Sprintf("renewal-%s-v1-%03d", stage, ordinal)
}

func renewalDigest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// The original protected response remains the installation anchor even after
// expiry. Verify its signed certificate/issuer during their validity overlap;
// Load separately validates the selected active generation at the current time.
func historicalResponse(response enrollment.Response, origin string, key *rsa.PublicKey) (*x509.Certificate, error) {
	leaf, _ := pem.Decode([]byte(response.Certificate))
	issuer, _ := pem.Decode([]byte(response.Authority))
	if leaf == nil || issuer == nil {
		return nil, ErrUnavailable
	}
	c, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil {
		return nil, ErrUnavailable
	}
	ca, err := x509.ParseCertificate(issuer.Bytes)
	if err != nil {
		return nil, ErrUnavailable
	}
	at := c.NotBefore
	if ca.NotBefore.After(at) {
		at = ca.NotBefore
	}
	return enrollment.ValidateResponse(response, origin, key, at)
}

func renewalSource(i *Identity, certificate *x509.Certificate) (enrollment.RenewalSource, error) {
	broker, err := i.Keys.Broker.PublicKey()
	if err != nil {
		return enrollment.RenewalSource{}, ErrUnavailable
	}
	return enrollment.RenewalSource{DeviceID: i.Response.DeviceID, TenantID: i.Response.TenantID, SiteID: i.Response.SiteID, Origin: i.Origin, Platform: i.Platform, Architecture: i.Architecture, BrokerKey: broker, Certificate: bytes.Clone(certificate.Raw)}, nil
}

func encodeRenewalCandidate(p *pending, source enrollment.RenewalSource, request enrollment.RenewalRequest, keys *enrollment.Keys, ordinal int) ([]byte, error) {
	if ordinal < 1 || ordinal > MaxIdentityRenewalAttempts {
		return nil, ErrUnavailable
	}
	private, err := encodePending(p.bootstrap, keys)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	proof, err := json.Marshal(request)
	if err != nil {
		return nil, ErrUnavailable
	}
	return encodeFields(renewalCandidateMagic, p.digest[:], []byte(strconv.Itoa(ordinal)), []byte(renewalDigest(source.Certificate)), proof, private)
}

func encodeRenewalPublic(magic string, binding [sha256.Size]byte, value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(data)
	return encodeFields(magic, binding[:], data)
}

func decodeRenewalPublic(data []byte, magic string, binding [sha256.Size]byte, target any) error {
	fields, err := decodeFields(data, magic, 2)
	if err != nil || !bytes.Equal(fields[0], binding[:]) || decodeCanonicalJSON(fields[1], target) != nil {
		return ErrUnavailable
	}
	return nil
}

func renewalTimeOrdered(at, after, now time.Time) bool {
	return !at.IsZero() && !at.After(now.Add(enrollment.RenewalClockSkew)) && !at.Before(after.Add(-enrollment.RenewalClockSkew))
}

func (s *Store) decodeRenewalAttempt(p *pending, state *renewalState, ordinal int, records [4][]byte) (*renewalAttempt, error) {
	fields, err := decodeFields(records[0], renewalCandidateMagic, 5)
	if err != nil || !bytes.Equal(fields[0], p.digest[:]) || string(fields[1]) != strconv.Itoa(ordinal) || string(fields[2]) != renewalDigest(state.source.Certificate) {
		return nil, ErrUnavailable
	}
	request, err := enrollment.DecodeRenewalRequest(fields[3])
	if err != nil {
		return nil, ErrUnavailable
	}
	created := time.Unix(request.IssuedAt, 0)
	if !renewalTimeOrdered(created, state.transition, s.renewalTime()) {
		return nil, ErrUnavailable
	}
	proof, err := enrollment.ValidateRenewalProof(*request, state.source, created)
	if err != nil {
		return nil, ErrUnavailable
	}
	private, err := decodePending(fields[4])
	if err != nil {
		return nil, ErrUnavailable
	}
	defer private.close()
	broker, err := private.keys.Broker.PublicKey()
	if err != nil || private.bootstrap != p.bootstrap || !private.keys.Certificate.PublicKey.Equal(proof.CertificateKey) || broker != proof.BrokerKey {
		return nil, ErrUnavailable
	}
	a := &renewalAttempt{ordinal: ordinal, keys: private.keys, request: *request, intent: proof.IntentDigest, digest: sha256.Sum256(records[0])}
	private.keys = nil
	valid := false
	defer func() {
		if !valid {
			a.close()
		}
	}()
	if records[1] != nil {
		var issued renewalIssuance
		if decodeRenewalPublic(records[1], renewalIssuedMagic, a.digest, &issued) != nil || !renewalTimeOrdered(issued.ReceivedAt, created, s.renewalTime()) {
			return nil, ErrUnavailable
		}
		proof, err := enrollment.ValidateRenewalProof(issued.Request, state.source, issued.ReceivedAt)
		if err != nil || proof.IntentDigest != a.intent {
			return nil, ErrUnavailable
		}
		target, err := enrollment.ValidatePreparedIdentityRenewal(issued.Prepared, issued.Request, state.source, issued.ReceivedAt)
		if err != nil {
			return nil, ErrUnavailable
		}
		a.issuance, a.target, a.issuanceDigest = &issued, target, sha256.Sum256(records[1])
	}
	if records[2] != nil {
		var decision renewalDecision
		if decodeRenewalPublic(records[2], renewalDecisionMagic, a.digest, &decision) != nil || !renewalTimeOrdered(decision.DecidedAt, created, s.renewalTime()) {
			return nil, ErrUnavailable
		}
		switch decision.Action {
		case "abandon":
			if decision.IssuanceDigest != "" {
				return nil, ErrUnavailable
			}
		case "confirm":
			if a.issuance == nil || decision.IssuanceDigest != hex.EncodeToString(a.issuanceDigest[:]) || !renewalTimeOrdered(decision.DecidedAt, a.issuance.ReceivedAt, s.renewalTime()) || !decision.DecidedAt.Before(a.issuance.Prepared.ExpiresAt) {
				return nil, ErrUnavailable
			}
		default:
			return nil, ErrUnavailable
		}
		a.decision, a.decisionDigest = &decision, sha256.Sum256(records[2])
	}
	if records[3] != nil {
		var active renewalActivation
		if a.decision == nil || a.decision.Action != "confirm" || decodeRenewalPublic(records[3], renewalActivatedMagic, a.decisionDigest, &active) != nil || !renewalTimeOrdered(active.ReceivedAt, a.decision.DecidedAt, s.renewalTime()) || !renewalTimeOrdered(active.Confirmed.ConfirmedAt, a.decision.DecidedAt, s.renewalTime()) || !active.Confirmed.ConfirmedAt.Before(a.issuance.Prepared.ExpiresAt) || enrollment.ValidateConfirmedIdentityRenewal(active.Confirmed, active.Request, *a.target, active.ReceivedAt) != nil {
			return nil, ErrUnavailable
		}
		a.activation = &active
	}
	valid = true
	return a, nil
}

// Every slot is inspected, including absent anchors and holes. A concurrent
// publisher can require a retry; an inconsistent snapshot never returns old keys
// after observing confirmation intent or a later generation.
func (s *Store) loadRenewalState(p *pending) (*renewalState, error) {
	i, err := s.loadOriginalIdentity(p)
	if err != nil {
		return nil, err
	}
	state := &renewalState{identity: i, next: 1}
	valid := false
	defer func() {
		if !valid {
			state.close()
		}
	}()
	cert, err := historicalResponse(i.Response, i.Origin, &i.Keys.Certificate.PublicKey)
	if err != nil {
		return nil, ErrUnavailable
	}
	state.source, err = renewalSource(i, cert)
	if err != nil {
		return nil, err
	}
	state.transition = cert.NotBefore
	i.certificates = map[string]renewalCertificate{renewalDigest(cert.Raw): {certificate: cert}}
	gap := false
	seenIDs := make(map[string]struct{})
	for ordinal := 1; ordinal <= MaxIdentityRenewalAttempts; ordinal++ {
		var records [4][]byte
		loadErr := func() error {
			for n, stage := range renewalStages {
				data, err := s.backend.Load(renewalRecord(stage, ordinal))
				if err != nil && !errors.Is(err, ErrMissing) {
					clear(data)
					return ErrUnavailable
				}
				if errors.Is(err, ErrMissing) {
					clear(data)
					continue
				}
				if len(data) == 0 {
					clear(data)
					return ErrUnavailable
				}
				records[n] = data
			}
			return nil
		}()
		if loadErr != nil {
			for _, data := range records {
				clear(data)
			}
			return nil, loadErr
		}
		if records[0] == nil {
			orphan := records[1] != nil || records[2] != nil || records[3] != nil
			for _, data := range records {
				clear(data)
			}
			if orphan {
				return nil, ErrUnavailable
			}
			gap = true
			continue
		}
		if gap || state.pending != nil {
			for _, data := range records {
				clear(data)
			}
			return nil, ErrUnavailable
		}
		a, err := s.decodeRenewalAttempt(p, state, ordinal, records)
		for _, data := range records {
			clear(data)
		}
		if err != nil {
			return nil, err
		}
		if _, exists := seenIDs[a.request.RequestID]; exists {
			a.close()
			return nil, ErrUnavailable
		}
		seenIDs[a.request.RequestID] = struct{}{}
		state.lastRequest, state.lastAction = a.request.RequestID, ""
		state.next = ordinal + 1
		if a.activation != nil {
			oldHash := renewalDigest(state.source.Certificate)
			old := i.certificates[oldHash]
			old.retiredAt = a.activation.Confirmed.ConfirmedAt
			i.certificates[oldHash] = old
			cert, err := enrollment.ValidateResponse(a.issuance.Prepared.Response, i.Origin, &a.keys.Certificate.PublicKey, a.activation.ReceivedAt)
			if err != nil {
				a.close()
				return nil, ErrUnavailable
			}
			releaseKeys(i.Keys)
			i.Keys, a.keys, i.Response = a.keys, nil, a.issuance.Prepared.Response
			i.certificates[renewalDigest(cert.Raw)] = renewalCertificate{certificate: cert}
			state.source = a.target.Candidate
			state.transition = a.activation.ReceivedAt
			state.lastAction = "activated"
		} else if a.decision != nil && a.decision.Action == "abandon" {
			state.lastAction = "abandon"
			state.transition = a.decision.DecidedAt
		} else {
			state.pending = a
			continue
		}
		a.close()
	}
	valid = true
	return state, nil
}
