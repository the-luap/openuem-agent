package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/windowssoftware"
)

type softwareJournal interface {
	Lookup(enrollment.SoftwareTask) (*enrollmentstore.SoftwareEntry, error)
	BeginWithBootSession(enrollment.SoftwareTask, *enrollment.SoftwareSecret, windowssoftware.BootSession) (bool, *enrollmentstore.SoftwareEntry, error)
	RecordResult(enrollment.SoftwareResult) error
}
type softwareExecutor func(context.Context, enrollment.SoftwarePlan) enrollment.SoftwareOutcome

// One joined service goroutine owns this client. The borrowed identity, native
// Store and installation service lease must remain live until it has stopped.
type softwareClient struct {
	identity               *enrollmentstore.Identity
	certificate, authority *x509.Certificate
	scope                  enrollment.SoftwareIdentity
	key                    *enrollment.SoftwareRecipientKey
	journal                softwareJournal
	live                   func() error
	bootSession            func() (windowssoftware.BootSession, error)
	recipientID            string
	pending                *enrollment.SoftwareResult
	persisted              bool
}

func newSoftwareClient(i *enrollmentstore.Identity, key *enrollment.SoftwareRecipientKey, journal softwareJournal, live func() error) (*softwareClient, error) {
	if i == nil || i.Platform != "windows" || i.Keys == nil || i.Keys.Certificate == nil || key == nil || !enrollment.ValidRecoveryPublicKey(key.PublicKey()) || journal == nil || live == nil || live() != nil {
		return nil, enrollment.ErrSoftware
	}
	cert, err := enrollment.ValidateResponse(i.Response, i.Origin, &i.Keys.Certificate.PublicKey, time.Now())
	if err != nil {
		return nil, enrollment.ErrSoftware
	}
	block, rest := pem.Decode([]byte(i.Response.Authority))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, enrollment.ErrSoftware
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !root.IsCA || cert.CheckSignatureFrom(root) != nil {
		return nil, enrollment.ErrSoftware
	}
	hash := sha256.Sum256(cert.Raw)
	return &softwareClient{identity: i, certificate: cert, authority: root, scope: enrollment.SoftwareIdentity{AgentID: i.Response.DeviceID, TenantID: i.Response.TenantID, SiteID: i.Response.SiteID, CertificateHash: hex.EncodeToString(hash[:])}, key: key, journal: journal, live: live, bootSession: windowssoftware.ReadBootSession}, nil
}

func (r *softwareClient) clearPending() {
	if r.pending != nil {
		clear(r.pending.Nonce)
	}
	r.pending, r.persisted = nil, false
}
func (r *softwareClient) close() {
	if r != nil {
		r.clearPending()
		r.key.Close()
	}
}
func (r *softwareClient) persistPending() error {
	if r == nil || r.journal == nil || r.live == nil || r.live() != nil {
		return enrollment.ErrSoftware
	}
	if r.pending == nil || r.persisted {
		return nil
	}
	if r.journal.RecordResult(*r.pending) != nil {
		return enrollment.ErrSoftware
	}
	r.persisted = true
	return nil
}
func (r *softwareClient) request(ctx context.Context, exchange recoveryExchange, request enrollment.SoftwareRequest) (*enrollment.SoftwareReply, error) {
	if ctx == nil || ctx.Err() != nil || exchange == nil || r.live() != nil {
		return nil, enrollment.ErrSoftware
	}
	request.Version, request.Protocol, request.AgentID = enrollment.SoftwareVersion, enrollment.SoftwareProtocol, r.scope.AgentID
	wire, err := json.Marshal(request)
	if err != nil || len(wire) > enrollment.MaxSoftwareMessage {
		return nil, enrollment.ErrSoftware
	}
	defer clear(wire)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	data, err := exchange(ctx, wire)
	if err != nil || ctx.Err() != nil {
		return nil, enrollment.ErrSoftware
	}
	defer clear(data)
	return enrollment.DecodeSoftwareReply(data, time.Now())
}
func (r *softwareClient) register(ctx context.Context, exchange recoveryExchange) error {
	public := r.key.PublicKey()
	reply, err := r.request(ctx, exchange, enrollment.SoftwareRequest{Action: "challenge", PublicKey: public})
	if err != nil {
		return err
	}
	if reply.Registration != nil {
		c := reply.Registration
		if !c.Valid(time.Now()) || c.Identity != r.scope || !bytes.Equal(c.PublicKey, public) {
			return enrollment.ErrSoftware
		}
		signature, err := enrollment.SignSoftwareRegistration(*c, r.certificate, r.identity.Keys.Certificate, time.Now())
		if err != nil {
			return enrollment.ErrSoftware
		}
		reply, err = r.request(ctx, exchange, enrollment.SoftwareRequest{Action: "register", Registration: c, Signature: signature})
		if err != nil || reply.Recipient == nil || reply.Recipient.ID != c.ID {
			return enrollment.ErrSoftware
		}
	}
	if reply.Recipient == nil || reply.Recipient.Identity != r.scope || !bytes.Equal(reply.Recipient.PublicKey, public) {
		return enrollment.ErrSoftware
	}
	r.recipientID = reply.Recipient.ID
	return nil
}
func (r *softwareClient) deliver(ctx context.Context, exchange recoveryExchange) error {
	if r.pending == nil || !r.persisted {
		return enrollment.ErrSoftware
	}
	proof, err := enrollment.SignSoftwareSubmission(*r.pending, r.scope, r.certificate, r.identity.Keys.Certificate, time.Now())
	if err != nil {
		return enrollment.ErrSoftware
	}
	receipt, err := enrollment.SoftwareResultReceipt(*r.pending, time.Now())
	if err != nil {
		return enrollment.ErrSoftware
	}
	reply, err := r.request(ctx, exchange, enrollment.SoftwareRequest{Action: "result", Result: r.pending, Submission: proof})
	if err != nil || reply.Receipt == nil || *reply.Receipt != *receipt {
		return enrollment.ErrSoftware
	}
	r.clearPending()
	return nil
}
func softwareInterrupted() enrollment.SoftwareOutcome {
	return enrollment.SoftwareOutcome{State: "uncertain", Execution: "unknown", Before: enrollment.SoftwareObservation{State: "unknown"}, After: enrollment.SoftwareObservation{State: "unknown"}, Error: "interrupted"}
}
func (r *softwareClient) produce(task enrollment.SoftwareTask, nonce []byte, outcome enrollment.SoftwareOutcome) error {
	hash, err := task.Digest()
	if err != nil {
		return enrollment.ErrSoftware
	}
	result, err := enrollment.SignSoftwareResult(task.Context, r.scope, hash, nonce, outcome, r.certificate, r.identity.Keys.Certificate, time.Now())
	if err != nil {
		return enrollment.ErrSoftware
	}
	r.pending, r.persisted = result, false
	return r.persistPending()
}
func (r *softwareClient) recoverEntry(task enrollment.SoftwareTask, entry *enrollmentstore.SoftwareEntry) error {
	if entry == nil || len(entry.Nonce) != 32 {
		return enrollment.ErrSoftware
	}
	want, err := task.Digest()
	got, gotErr := entry.Task.Digest()
	if err != nil || gotErr != nil || want != got {
		return enrollment.ErrSoftware
	}
	if entry.Result == nil {
		// A free process lease does not prove delegated Windows Installer work
		// stopped. Preserve uncertainty and its server reservation; never rerun.
		return r.produce(task, entry.Nonce, softwareInterrupted())
	}
	result := entry.Result
	cert, err := x509.ParseCertificate(result.Certificate)
	if err != nil || cert.CheckSignatureFrom(r.authority) != nil || !result.Context.Equal(task.Context) || result.TaskHash != want || !bytes.Equal(result.Nonce, entry.Nonce) || enrollment.VerifySoftwareResult(*result, cert, time.Now()) != nil {
		return enrollment.ErrSoftware
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.authority)
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Unix(result.SignedAt, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return enrollment.ErrSoftware
	}
	r.pending, r.persisted = result, true
	entry.Result = nil
	return nil
}

func (r *softwareClient) cycle(ctx context.Context, exchange recoveryExchange, execute softwareExecutor) error {
	if r == nil || ctx == nil || exchange == nil || execute == nil || r.identity == nil || r.identity.Keys == nil || r.key == nil {
		return enrollment.ErrSoftware
	}
	// Persist a completed native result even when service cancellation prevents
	// another network request. It must not be replaced by an invented outcome.
	if r.persistPending() != nil || ctx.Err() != nil || !time.Now().Before(r.certificate.NotAfter) {
		return enrollment.ErrSoftware
	}
	if r.pending != nil {
		return r.deliver(ctx, exchange)
	}
	if r.recipientID == "" {
		if err := r.register(ctx, exchange); err != nil {
			return err
		}
	}
	reply, err := r.request(ctx, exchange, enrollment.SoftwareRequest{Action: "poll", RecipientID: r.recipientID})
	if err != nil {
		r.recipientID = ""
		return err
	}
	if reply.Task == nil {
		if reply.Recipient != nil || reply.Registration != nil || reply.Receipt != nil {
			return enrollment.ErrSoftware
		}
		return nil
	}
	task := *reply.Task
	if task.Context.Identity.AgentID != r.scope.AgentID || task.Context.Identity.TenantID != r.scope.TenantID || task.Context.Identity.SiteID != r.scope.SiteID || enrollment.VerifySoftwareTaskHistory(task, r.authority) != nil {
		return enrollment.ErrSoftware
	}
	entry, err := r.journal.Lookup(task)
	if err != nil {
		return enrollment.ErrSoftware
	}
	if entry != nil {
		defer entry.Close()
		if r.recoverEntry(task, entry) != nil {
			return enrollment.ErrSoftware
		}
		return r.deliver(ctx, exchange)
	}
	secret, err := r.key.Open(task, r.authority, r.scope, r.recipientID, time.Now())
	if err != nil {
		return enrollment.ErrSoftware
	}
	defer secret.Close()
	if r.bootSession == nil {
		return enrollment.ErrSoftware
	}
	boot, err := r.bootSession()
	if err != nil || !boot.Valid() {
		return enrollment.ErrSoftware
	}
	won, entry, err := r.journal.BeginWithBootSession(task, secret, boot)
	if err != nil || entry == nil {
		return enrollment.ErrSoftware
	}
	defer entry.Close()
	if !won {
		if r.recoverEntry(task, entry) != nil {
			return enrollment.ErrSoftware
		}
		return r.deliver(ctx, exchange)
	}
	// A changed native session after durable admission cannot authorize starting
	// this installer under a different boot. Retain intent and recover as uncertain.
	current, err := r.bootSession()
	if err != nil || current != boot || entry.BootSession != boot {
		return enrollment.ErrSoftware
	}
	deadline := time.Unix(task.Context.ExpiresAt, 0)
	if signDeadline := r.certificate.NotAfter.Add(-30 * time.Second); signDeadline.Before(deadline) {
		deadline = signDeadline
	}
	work, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	outcome := enrollment.SoftwareOutcome{State: "not_started", Execution: "not_started", Before: enrollment.SoftwareObservation{State: "unknown"}, After: enrollment.SoftwareObservation{State: "unknown"}, Error: "unavailable"}
	if work.Err() == nil && r.live() == nil {
		outcome = execute(work, secret.Plan)
		if !outcome.ValidFor(secret.Plan) || work.Err() != nil && outcome.Execution != "not_started" {
			outcome = softwareInterrupted()
		}
	}
	if err = r.produce(task, entry.Nonce, outcome); err != nil {
		return err
	}
	return r.deliver(ctx, exchange)
}
