package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/macsecurity"
)

// A single runtime goroutine owns the recipient epoch and pending receipt.
// Recovery plaintext exists only during the bounded local validation call.
type recoveryClient struct {
	identity    *enrollmentstore.Identity
	certificate *x509.Certificate
	scope       enrollment.RecoveryIdentity
	key         *enrollment.RecoveryRecipientKey
	recipientID string
	pending     *enrollment.RecoveryResult
}

type recoveryExchange func(context.Context, []byte) ([]byte, error)
type recoveryValidator func(context.Context, []byte) (bool, error)

func newRecoveryClient(i *enrollmentstore.Identity, key *enrollment.RecoveryRecipientKey) (*recoveryClient, error) {
	if i == nil || i.Platform != "macos" || i.Keys == nil || i.Keys.Certificate == nil || key == nil || !enrollment.ValidRecoveryPublicKey(key.PublicKey()) {
		return nil, enrollment.ErrRecovery
	}
	cert, err := enrollment.ValidateResponse(i.Response, i.Origin, &i.Keys.Certificate.PublicKey, time.Now())
	if err != nil {
		return nil, enrollment.ErrRecovery
	}
	hash := sha256.Sum256(cert.Raw)
	return &recoveryClient{identity: i, certificate: cert, key: key,
		scope: enrollment.RecoveryIdentity{AgentID: i.Response.DeviceID, TenantID: i.Response.TenantID, SiteID: i.Response.SiteID, CertificateHash: hex.EncodeToString(hash[:])}}, nil
}

func (r *recoveryClient) clearPending() {
	if r.pending != nil {
		clear(r.pending.Nonce)
		r.pending = nil
	}
}

func (r *recoveryClient) close() {
	if r != nil {
		r.clearPending()
		r.key.Close()
	}
}

func (r *recoveryClient) request(ctx context.Context, exchange recoveryExchange, request enrollment.RecoveryRequest) (*enrollment.RecoveryReply, error) {
	if ctx.Err() != nil {
		return nil, enrollment.ErrRecovery
	}
	request.Version, request.AgentID = enrollment.RecoveryVersion, r.scope.AgentID
	data, err := json.Marshal(request)
	if err != nil || len(data) > enrollment.MaxRecoveryMessage {
		return nil, enrollment.ErrRecovery
	}
	defer clear(data)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := exchange(ctx, data)
	if err != nil {
		return nil, enrollment.ErrRecovery
	}
	return enrollment.DecodeRecoveryReply(response)
}

func (r *recoveryClient) register(ctx context.Context, exchange recoveryExchange) error {
	public := r.key.PublicKey()
	reply, err := r.request(ctx, exchange, enrollment.RecoveryRequest{Action: "challenge", PublicKey: public})
	if err != nil {
		return err
	}
	if reply.Registration != nil {
		c := reply.Registration
		if !c.Valid(time.Now()) || c.Identity != r.scope || !bytes.Equal(c.PublicKey, public) {
			return enrollment.ErrRecovery
		}
		signature, err := enrollment.SignRecoveryRegistration(*c, r.certificate, r.identity.Keys.Certificate, time.Now())
		if err != nil {
			return enrollment.ErrRecovery
		}
		reply, err = r.request(ctx, exchange, enrollment.RecoveryRequest{Action: "register", Registration: c, Signature: signature})
		if err != nil {
			return err
		}
		if reply.Recipient == nil || reply.Recipient.ID != c.ID {
			return enrollment.ErrRecovery
		}
	}
	if reply.Recipient == nil || !reply.Recipient.Valid() || reply.Recipient.Identity != r.scope || !bytes.Equal(reply.Recipient.PublicKey, public) {
		return enrollment.ErrRecovery
	}
	r.recipientID = reply.Recipient.ID
	if r.pending != nil && r.pending.Context.RecipientID != r.recipientID {
		r.clearPending()
	}
	return nil
}

func (r *recoveryClient) cycle(ctx context.Context, exchange recoveryExchange, validate recoveryValidator) error {
	if ctx == nil || ctx.Err() != nil || exchange == nil || validate == nil || !time.Now().Before(r.certificate.NotAfter) {
		return enrollment.ErrRecovery
	}
	if r.pending != nil && !r.pending.Context.Valid(time.Now()) {
		r.clearPending()
	}
	if r.recipientID == "" {
		if err := r.register(ctx, exchange); err != nil {
			return err
		}
	}
	if r.pending == nil {
		reply, err := r.request(ctx, exchange, enrollment.RecoveryRequest{Action: "poll", RecipientID: r.recipientID})
		if err != nil {
			r.recipientID = ""
			return err
		}
		if reply.Recipient != nil || reply.Registration != nil {
			return enrollment.ErrRecovery
		}
		if reply.Task == nil {
			return nil
		}
		secret, err := r.key.Open(*reply.Task, r.scope, r.recipientID, time.Now())
		if err != nil {
			return enrollment.ErrRecovery
		}
		// Clearing is immediate after the OS check and signature, before network
		// delivery. Retries retain only the nonce and authenticated outcome.
		func() {
			defer secret.Close()
			check, cancel := context.WithDeadline(ctx, time.Unix(reply.Task.Context.ExpiresAt, 0))
			defer cancel()
			check, stop := context.WithTimeout(check, 15*time.Second)
			defer stop()
			valid, checkErr := validate(check, secret.Key())
			if check.Err() != nil {
				checkErr = check.Err()
			}
			outcome := "invalid"
			if checkErr != nil {
				outcome = "unavailable"
			} else if valid {
				outcome = "valid"
			}
			if errors.Is(checkErr, macsecurity.ErrUnsupported) {
				outcome = "unsupported"
			}
			r.pending, err = secret.Result(outcome, r.certificate, r.identity.Keys.Certificate, time.Now())
		}()
		if err != nil {
			return enrollment.ErrRecovery
		}
	}
	reply, err := r.request(ctx, exchange, enrollment.RecoveryRequest{Action: "result", Result: r.pending})
	if err != nil {
		r.recipientID = ""
		return err
	}
	if reply.Task != nil || reply.Recipient != nil || reply.Registration != nil {
		return enrollment.ErrRecovery
	}
	r.clearPending()
	return nil
}

func (a *Agent) setRecoveryCapability(version int) {
	r := a.individual
	if r == nil {
		return
	}
	accepted := int32(0)
	if version == enrollment.RecoveryVersion && r.recovery != nil {
		accepted = int32(version)
	}
	r.recoveryVersion.Store(accepted)
	if accepted == 0 {
		return
	}
	r.mu.Lock()
	if r.stopping || r.recoveryStarted {
		r.mu.Unlock()
		return
	}
	r.recoveryStarted = true
	r.work.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.work.Done()
		defer r.recovery.clearPending()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		exchange := func(ctx context.Context, data []byte) ([]byte, error) {
			r.mu.Lock()
			connection := r.connection
			r.mu.Unlock()
			if connection == nil || connection.IsClosed() {
				return nil, enrollment.ErrRecovery
			}
			subject, err := enrollment.RequestSubject(r.identity.Response.DeviceID, "recovery")
			if err != nil {
				return nil, enrollment.ErrRecovery
			}
			message, err := connection.RequestWithContext(ctx, subject, data)
			if err != nil || message == nil {
				return nil, enrollment.ErrRecovery
			}
			return message.Data, nil
		}
		for {
			if r.recoveryVersion.Load() == enrollment.RecoveryVersion {
				if r.recovery.cycle(r.ctx, exchange, macsecurity.ValidateFileVaultRecoveryKey) != nil && r.ctx.Err() == nil {
					log.Print("[ERROR]: private FileVault validation request failed")
				}
			} else {
				r.recovery.clearPending()
			}
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
