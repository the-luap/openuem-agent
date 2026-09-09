package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/macsecurity"
)

type rotationJournal interface {
	Lookup(enrollment.RotationContext) (*enrollmentstore.RotationEntry, error)
	BeginWithBootSession(enrollment.RotationTask, []byte, string) (bool, *enrollmentstore.RotationEntry, error)
	RecordResult(enrollment.RotationResult) error
}

type rotationLocalResult interface {
	Outcome() string
	ExecutionStopped() bool
	Key() []byte
	Close()
}

type rotationRunner func(context.Context, []byte) rotationLocalResult
type rotationLeaseFactory func() (io.Closer, rotationRunner, error)

// The existing recovery goroutine owns both protocols and their shared recipient
// epoch. Pending holds only signed encrypted material, never an old/new PRK.
type rotationClient struct {
	recovery    *recoveryClient
	journal     rotationJournal
	lease       rotationLeaseFactory
	pending     *enrollment.RotationResult
	persisted   bool
	bootSession func() (string, error)
}

func newRotationClient(recovery *recoveryClient, journal rotationJournal, directory string) (*rotationClient, error) {
	if recovery == nil || recovery.identity == nil || recovery.identity.Platform != "macos" || recovery.certificate == nil || !recovery.scope.Valid() || journal == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, enrollment.ErrRecovery
	}
	return &rotationClient{recovery: recovery, journal: journal, bootSession: macsecurity.BootSessionID, lease: func() (io.Closer, rotationRunner, error) {
		lease, err := macsecurity.AcquireFileVaultLease(directory)
		if err != nil {
			return nil, nil, err
		}
		return lease, func(ctx context.Context, key []byte) rotationLocalResult {
			return macsecurity.RotateFileVaultRecoveryKey(ctx, lease, key)
		}, nil
	}}, nil
}

func (r *rotationClient) clearPending() {
	if r != nil {
		if r.pending != nil {
			clear(r.pending.Nonce)
		}
		r.pending, r.persisted = nil, false
	}
}

func (r *rotationClient) request(ctx context.Context, exchange recoveryExchange, request enrollment.RotationRequest) (*enrollment.RotationReply, error) {
	if ctx == nil || ctx.Err() != nil || exchange == nil {
		return nil, enrollment.ErrRecovery
	}
	request.Version, request.Protocol, request.AgentID = enrollment.RotationVersion, enrollment.RotationProtocol, r.recovery.scope.AgentID
	data, err := json.Marshal(request)
	if err != nil || len(data) > enrollment.MaxRecoveryMessage {
		return nil, enrollment.ErrRecovery
	}
	defer clear(data)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reply, err := exchange(ctx, data)
	if err != nil {
		return nil, enrollment.ErrRecovery
	}
	return enrollment.DecodeRotationReply(reply, time.Now())
}

// Persistence is independent of network/shutdown cancellation. The key has
// already changed, so cancelled network work must not discard its receipt.
func (r *rotationClient) persistLocked() error {
	if r.pending == nil || r.persisted {
		return nil
	}
	if err := r.journal.RecordResult(*r.pending); err != nil {
		return enrollment.ErrRecovery
	}
	r.persisted = true
	return nil
}

func (r *rotationClient) persistPending() error {
	if r == nil || r.pending == nil || r.persisted {
		return nil
	}
	if r.lease == nil || r.journal == nil {
		return enrollment.ErrRecovery
	}
	lease, _, err := r.lease()
	if err != nil || lease == nil {
		return enrollment.ErrRecovery
	}
	defer lease.Close()
	return r.persistLocked()
}

func (r *rotationClient) deliver(ctx context.Context, exchange recoveryExchange) error {
	if r.pending == nil {
		return nil
	}
	if !r.persisted {
		return enrollment.ErrRecovery
	}
	if r.pending.Context.Binding.RecipientID != r.recovery.recipientID {
		// The immutable journal retains the encrypted candidate even when the
		// service replaces its recipient epoch and will no longer accept it.
		r.clearPending()
		return nil
	}
	reply, err := r.request(ctx, exchange, enrollment.RotationRequest{Action: "result", Result: r.pending})
	if err != nil {
		r.recovery.recipientID = ""
		return enrollment.ErrRecovery
	}
	if reply.Task != nil || reply.Receipt != nil {
		return enrollment.ErrRecovery
	}
	r.clearPending()
	return nil
}

func (r *rotationClient) produce(c enrollment.RotationContext, nonce []byte, outcome string, key []byte) error {
	result, err := enrollment.NewRotationResult(c, outcome, nonce, key, r.recovery.certificate, r.recovery.identity.Keys.Certificate, time.Now())
	if err != nil {
		return enrollment.ErrRecovery
	}
	r.pending, r.persisted = result, false
	return r.persistLocked()
}

func (r *rotationClient) produceStopped(c enrollment.RotationContext, nonce []byte) error {
	result, err := enrollment.NewStoppedRotationResult(c, nonce, r.recovery.certificate, r.recovery.identity.Keys.Certificate, time.Now())
	if err != nil {
		return enrollment.ErrRecovery
	}
	r.pending, r.persisted = result, false
	return r.persistLocked()
}

func (r *rotationClient) recoverEntry(c enrollment.RotationContext, entry *enrollmentstore.RotationEntry) error {
	if entry == nil || entry.Context != c || len(entry.Nonce) != 32 {
		return enrollment.ErrRecovery
	}
	if entry.Result == nil {
		// The parent lease can be free while an orphaned OS command is alive.
		// A different kernel boot excludes that process; elapsed wall time or
		// another agent PID does not. Never replay an existing intent.
		if r.bootSession == nil || !enrollment.ValidDeviceID(entry.BootSessionID) {
			return nil
		}
		boot, err := r.bootSession()
		if err != nil || !enrollment.ValidDeviceID(boot) {
			return enrollment.ErrRecovery
		}
		if boot == entry.BootSessionID {
			return nil
		}
		return r.produceStopped(c, entry.Nonce)
	}
	if entry.Result.Context != c || !bytes.Equal(entry.Result.Nonce, entry.Nonce) || enrollment.VerifyRotationResult(*entry.Result, r.recovery.certificate, time.Now()) != nil {
		return enrollment.ErrRecovery
	}
	r.pending, r.persisted = entry.Result, true
	return nil
}

func (r *rotationClient) cycle(ctx context.Context, registration, exchange recoveryExchange) error {
	if r == nil || r.recovery == nil || r.recovery.certificate == nil || r.recovery.identity == nil || r.recovery.identity.Keys == nil || r.journal == nil || r.lease == nil || ctx == nil || registration == nil || exchange == nil {
		return enrollment.ErrRecovery
	}
	if err := r.persistPending(); err != nil {
		return err
	}
	if ctx.Err() != nil || !time.Now().Before(r.recovery.certificate.NotAfter) {
		return enrollment.ErrRecovery
	}
	if r.recovery.recipientID == "" {
		if err := r.recovery.register(ctx, registration); err != nil {
			return err
		}
	}
	if r.pending != nil {
		return r.deliver(ctx, exchange)
	}
	reply, err := r.request(ctx, exchange, enrollment.RotationRequest{Action: "poll", RecipientID: r.recovery.recipientID})
	if err != nil {
		r.recovery.recipientID = ""
		return enrollment.ErrRecovery
	}
	if reply.Task == nil && reply.Receipt == nil {
		return nil
	}
	var c enrollment.RotationContext
	if reply.Task != nil {
		c = reply.Task.Context
	} else {
		c = *reply.Receipt
	}
	if c.Binding.Identity != r.recovery.scope || c.Binding.RecipientID != r.recovery.recipientID {
		return enrollment.ErrRecovery
	}
	lease, run, err := r.lease()
	if errors.Is(err, macsecurity.ErrRotationBusy) {
		return nil
	}
	if err != nil || lease == nil || run == nil {
		if lease != nil {
			lease.Close()
		}
		return enrollment.ErrRecovery
	}
	err = func() error {
		defer lease.Close()
		if ctx.Err() != nil {
			return enrollment.ErrRecovery
		}
		entry, err := r.journal.Lookup(c)
		if err != nil {
			return enrollment.ErrRecovery
		}
		if entry != nil {
			return r.recoverEntry(c, entry)
		}
		if reply.Task == nil {
			return enrollment.ErrRecovery
		}
		secret, err := r.recovery.key.OpenRotationTask(*reply.Task, r.recovery.scope, r.recovery.recipientID, time.Now())
		if err != nil {
			return enrollment.ErrRecovery
		}
		defer secret.Close()
		if r.bootSession == nil {
			return enrollment.ErrRecovery
		}
		boot, err := r.bootSession()
		if err != nil || !enrollment.ValidDeviceID(boot) {
			return enrollment.ErrRecovery
		}
		admitted, entry, err := r.journal.BeginWithBootSession(*reply.Task, secret.Nonce(), boot)
		if err != nil {
			return enrollment.ErrRecovery
		}
		if !admitted {
			return r.recoverEntry(c, entry)
		}
		deadline := time.Unix(c.Binding.ExpiresAt, 0)
		certificateDeadline := r.recovery.certificate.NotAfter.Add(-enrollment.RotationReceiptGrace)
		if certificateDeadline.Before(deadline) {
			deadline = certificateDeadline
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return r.produce(c, secret.Nonce(), "unavailable", nil)
		}
		mutation, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		local := run(mutation, secret.Key())
		if local == nil {
			return nil
		}
		defer local.Close()
		outcome, key := local.Outcome(), local.Key()
		if len(key) > 0 {
			if !enrollment.ValidFileVaultRecoveryKey(key) || bytes.Equal(key, secret.Key()) {
				outcome, key = "uncertain", nil
			} else if outcome != "rotated" && outcome != "unverified" {
				outcome = "unverified"
			}
		} else {
			switch outcome {
			case "invalid", "unavailable", "unsupported", "uncertain":
			default:
				outcome = "uncertain"
			}
		}
		if outcome == "uncertain" {
			if !local.ExecutionStopped() {
				return nil
			}
			return r.produceStopped(c, secret.Nonce())
		}
		return r.produce(c, secret.Nonce(), outcome, key)
	}()
	if err != nil {
		return err
	}
	return r.deliver(ctx, exchange)
}
