package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/windowssoftware"
)

type softwareReconciliationJournal interface {
	LookupSoftwareOriginal(enrollment.SoftwareReconciliationTask) (*enrollmentstore.SoftwareEntry, error)
	LookupSoftwareReconciliation(enrollment.SoftwareReconciliationTask) (*enrollmentstore.SoftwareReconciliationEntry, error)
	NextSoftwareReconciliation() (*enrollmentstore.SoftwareReconciliationEntry, error)
	RecordSoftwareReconciliation(enrollment.SoftwareReconciliationTask, enrollment.SoftwareReconciliationResult) error
	AcknowledgeSoftwareReconciliation(enrollment.SoftwareReceipt) error
}

type softwareObserver func(context.Context, windowssoftware.Rule) (windowssoftware.Observation, error)

func (r *softwareClient) reconciliationJournal() softwareReconciliationJournal {
	if r == nil {
		return nil
	}
	j, _ := r.journal.(softwareReconciliationJournal)
	return j
}

func (r *softwareClient) clearReconciliation() {
	if r.reconciliationPending != nil {
		r.reconciliationPending.Close()
	}
	r.reconciliationPending, r.reconciliationPersisted = nil, false
}

func (r *softwareClient) persistReconciliation() error {
	if r.reconciliationPending == nil || r.reconciliationPersisted {
		return nil
	}
	j := r.reconciliationJournal()
	if j == nil || r.live() != nil || j.RecordSoftwareReconciliation(r.reconciliationPending.Task, r.reconciliationPending.Result) != nil {
		return enrollment.ErrSoftware
	}
	r.reconciliationPersisted = true
	return nil
}

func (r *softwareClient) reconciliationRequest(ctx context.Context, exchange recoveryExchange, request enrollment.SoftwareReconciliationRequest) (*enrollment.SoftwareReconciliationReply, error) {
	if ctx == nil || ctx.Err() != nil || exchange == nil || r.live() != nil {
		return nil, enrollment.ErrSoftware
	}
	request.Version, request.Protocol, request.AgentID = enrollment.SoftwareReconciliationVersion, enrollment.SoftwareReconciliationProtocol, r.scope.AgentID
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
	return enrollment.DecodeSoftwareReconciliationReply(data, time.Now())
}

func (r *softwareClient) recoverReconciliation(entry *enrollmentstore.SoftwareReconciliationEntry) error {
	if entry == nil {
		return enrollment.ErrSoftware
	}
	task, result := entry.Task, entry.Result
	identity := task.Context.Identity
	if identity.AgentID != r.scope.AgentID || identity.TenantID != r.scope.TenantID || identity.SiteID != r.scope.SiteID || enrollment.VerifySoftwareReconciliationTaskHistory(task, r.authority) != nil || !result.Context.Equal(task.Context) {
		return enrollment.ErrSoftware
	}
	hash, err := task.Digest()
	cert, certErr := x509.ParseCertificate(result.Certificate)
	if err != nil || result.TaskHash != hash || certErr != nil || cert.CheckSignatureFrom(r.authority) != nil || enrollment.VerifySoftwareReconciliationResult(result, cert, time.Now()) != nil {
		return enrollment.ErrSoftware
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.authority)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Unix(result.SignedAt, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return enrollment.ErrSoftware
	}
	original, err := r.reconciliationJournal().LookupSoftwareOriginal(task)
	if err != nil {
		return enrollment.ErrSoftware
	}
	if original == nil {
		if result.Outcome.State != "unavailable" {
			return enrollment.ErrSoftware
		}
	} else {
		defer original.Close()
		nonceHash := sha256.Sum256(original.Nonce)
		if len(original.Nonce) != 32 || enrollment.VerifySoftwareReconciliationEvidence(task, original.Task, result, r.authority, hex.EncodeToString(nonceHash[:]), time.Now()) != nil || result.Outcome.State != "unavailable" && (!original.BootSession.Valid() || result.Outcome.Admission != original.BootSession) {
			return enrollment.ErrSoftware
		}
	}
	r.reconciliationPending, r.reconciliationPersisted = entry, true
	return nil
}

func (r *softwareClient) deliverReconciliation(ctx context.Context, exchange recoveryExchange) error {
	entry := r.reconciliationPending
	if entry == nil || !r.reconciliationPersisted {
		return enrollment.ErrSoftware
	}
	proof, err := enrollment.SignSoftwareReconciliationSubmission(entry.Result, r.scope, r.certificate, r.identity.Keys.Certificate, time.Now())
	if err != nil {
		return enrollment.ErrSoftware
	}
	want, err := enrollment.SoftwareReconciliationReceipt(entry.Result, time.Now())
	if err != nil {
		return enrollment.ErrSoftware
	}
	reply, err := r.reconciliationRequest(ctx, exchange, enrollment.SoftwareReconciliationRequest{Action: "result", Result: &entry.Result, Submission: proof})
	if err != nil || reply.Receipt == nil || *reply.Receipt != *want || r.reconciliationJournal().AcknowledgeSoftwareReconciliation(*want) != nil {
		return enrollment.ErrSoftware
	}
	r.clearReconciliation()
	return nil
}

func softwareReconciliationUnavailable() enrollment.SoftwareReconciliationOutcome {
	return enrollment.SoftwareReconciliationOutcome{State: "unavailable", Observation: enrollment.SoftwareObservation{State: "unknown"}}
}

func (r *softwareClient) observeReconciliation(ctx context.Context, task enrollment.SoftwareReconciliationTask, original *enrollmentstore.SoftwareEntry, observe softwareObserver) (enrollment.SoftwareReconciliationOutcome, []byte, error) {
	unavailable := softwareReconciliationUnavailable()
	if original == nil {
		return unavailable, nil, nil
	}
	hash, err := original.Task.Digest()
	if err != nil || hash != task.Context.OriginalTaskHash || !original.Task.Context.Equal(task.Context.Original) || enrollment.VerifySoftwareTaskHistory(original.Task, r.authority) != nil || len(original.Nonce) != 32 {
		return unavailable, nil, enrollment.ErrSoftware
	}
	if !original.BootSession.Valid() || r.bootSession == nil {
		return unavailable, nil, nil
	}
	boot, err := r.bootSession()
	if err != nil || !boot.Valid() {
		return unavailable, nil, nil
	}
	outcome := enrollment.SoftwareReconciliationOutcome{State: "waiting_for_boot", Admission: original.BootSession, Current: boot, Observation: enrollment.SoftwareObservation{State: "unknown"}}
	if !boot.After(original.BootSession) {
		return outcome, bytes.Clone(original.Nonce), nil
	}
	if ctx.Err() != nil || r.live() != nil {
		return unavailable, nil, enrollment.ErrSoftware
	}
	d := task.Context.Original.Expectation.Detection
	observation, observationErr := observe(ctx, windowssoftware.Rule{Kind: d.Kind, ProductCode: d.ProductCode, UninstallKey: d.UninstallKey, RegistryView: d.RegistryView, Version: d.Version})
	after, err := r.bootSession()
	if err != nil || after != boot {
		return unavailable, nil, nil
	}
	outcome.State = "unknown"
	if observationErr == nil && ctx.Err() == nil && observation.Valid() {
		value := enrollment.SoftwareObservation{State: observation.State, Version: observation.Version}
		if value.Valid() && value.State != "unknown" {
			outcome.State, outcome.Observation = "drifted", value
			expected := task.Context.Original.Expectation
			if expected.Operation == "install" && value.Matches(expected.Detection) || expected.Operation == "remove" && value.State == "absent" {
				outcome.State = "observed"
			}
		}
	}
	return outcome, bytes.Clone(original.Nonce), nil
}

// The existing joined software owner also runs this read-only cycle. It has no
// executor or artifact input and never decrypts a new installer plan. Pending
// durable evidence is submitted before polling for another observation.
func (r *softwareClient) reconcile(ctx context.Context, exchange recoveryExchange, observe softwareObserver) error {
	if r == nil || ctx == nil || exchange == nil || observe == nil || r.identity == nil || r.identity.Keys == nil || r.reconciliationJournal() == nil {
		return enrollment.ErrSoftware
	}
	if r.persistPending() != nil || ctx.Err() != nil || !time.Now().Before(r.certificate.NotAfter) {
		return enrollment.ErrSoftware
	}
	if r.reconciliationPending == nil {
		entry, err := r.reconciliationJournal().NextSoftwareReconciliation()
		if err != nil {
			return enrollment.ErrSoftware
		}
		if entry != nil {
			if r.recoverReconciliation(entry) != nil {
				entry.Close()
				return enrollment.ErrSoftware
			}
		}
	}
	if r.reconciliationPending != nil {
		return r.deliverReconciliation(ctx, exchange)
	}
	reply, err := r.reconciliationRequest(ctx, exchange, enrollment.SoftwareReconciliationRequest{Action: "poll"})
	if err != nil {
		return err
	}
	if reply.Task == nil {
		if reply.Receipt != nil {
			return enrollment.ErrSoftware
		}
		return nil
	}
	task := *reply.Task
	if enrollment.VerifySoftwareReconciliationTask(task, r.authority, r.scope, time.Now()) != nil {
		return enrollment.ErrSoftware
	}
	entry, err := r.reconciliationJournal().LookupSoftwareReconciliation(task)
	if err != nil {
		return enrollment.ErrSoftware
	}
	if entry != nil {
		if r.recoverReconciliation(entry) != nil {
			entry.Close()
			return enrollment.ErrSoftware
		}
		if entry.Acknowledged {
			r.clearReconciliation()
			return nil
		}
		return r.deliverReconciliation(ctx, exchange)
	}
	original, err := r.reconciliationJournal().LookupSoftwareOriginal(task)
	if err != nil {
		return enrollment.ErrSoftware
	}
	if original != nil {
		defer original.Close()
	}
	deadline := time.Unix(task.Context.ExpiresAt, 0)
	if signing := r.certificate.NotAfter.Add(-30 * time.Second); signing.Before(deadline) {
		deadline = signing
	}
	work, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	outcome, nonce, err := r.observeReconciliation(work, task, original, observe)
	defer clear(nonce)
	if err != nil || r.live() != nil {
		return enrollment.ErrSoftware
	}
	hash, err := task.Digest()
	if err != nil {
		return enrollment.ErrSoftware
	}
	result, err := enrollment.SignSoftwareReconciliationResult(task.Context, hash, nonce, outcome, r.certificate, r.identity.Keys.Certificate, time.Now())
	if err != nil {
		return enrollment.ErrSoftware
	}
	r.reconciliationPending, r.reconciliationPersisted = &enrollmentstore.SoftwareReconciliationEntry{Task: task, Result: *result}, false
	if r.persistReconciliation() != nil {
		return enrollment.ErrSoftware
	}
	return r.deliverReconciliation(ctx, exchange)
}
