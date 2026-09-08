package enrollmentstore

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/bootstrap"
)

// EnrollVerified connects an independently verified signed configuration to
// durable pending state. The caller must authorize its origin/signing keys and
// complete native package/signature verification before invoking this method.
// The durable checkpoint is rechecked here; a concurrent different bootstrap
// still loses exclusive pending publication and cannot send a replacement claim.
func (s *Store) EnrollVerified(ctx context.Context, verified *bootstrap.Verified, deviceName string, roots *x509.CertPool) (*Identity, error) {
	return s.enrollVerified(ctx, verified, deviceName, roots, nil)
}

// EnrollInstalled requires a signed installed-agent binding and a native
// admission check for the retained executable and installer. Admission runs
// before pending state, immediately before a claim, and before publishing or
// returning an identity. It must not call Store methods: the latter checks run
// while the store holds its lifetime lock. A failed post-claim check preserves
// the pending keys so the same bootstrap can recover an issued response.
func (s *Store) EnrollInstalled(ctx context.Context, verified *bootstrap.Verified, deviceName string, roots *x509.CertPool, admission func(context.Context) error) (*Identity, error) {
	if verified == nil || admission == nil {
		return nil, ErrUnavailable
	}
	if err := verified.ValidAt(time.Now(), artifacts.Checkpoint{}); err != nil {
		return nil, err
	}
	artifact := verified.Artifact()
	if artifact.AgentSize <= 0 || artifact.AgentSHA256 == "" {
		return nil, artifacts.ErrAgentBinding
	}
	return s.enrollVerified(ctx, verified, deviceName, roots, admission)
}

func (s *Store) enrollVerified(ctx context.Context, verified *bootstrap.Verified, deviceName string, roots *x509.CertPool, admission func(context.Context) error) (*Identity, error) {
	if s == nil || ctx == nil || verified == nil {
		return nil, ErrUnavailable
	}
	config := verified.Config()
	b := Bootstrap{Origin: config.Origin, Invitation: config.Invitation, Platform: config.Platform, Architecture: config.Architecture, DeviceName: deviceName, ReleaseDigest: config.ReleaseDigest, TenantID: config.TenantID, SiteID: config.SiteID}
	if !b.valid() || b.TenantID <= 0 || b.SiteID <= 0 {
		return nil, ErrUnavailable
	}
	checkpoint, err := s.Checkpoint()
	if err != nil {
		return nil, err
	}
	check := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verified.ValidAt(time.Now(), checkpoint); err != nil {
			return err
		}
		if admission != nil {
			if err := admission(ctx); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return verified.ValidAt(time.Now(), checkpoint)
	}
	if err := check(ctx); err != nil {
		return nil, err
	}
	b.ReleaseSequence = verified.Checkpoint().Sequence
	client, err := enrollment.NewHTTPClient(b.Origin, roots)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer client.CloseIdleConnections()
	return s.enrollAdmitted(ctx, b, client.Claim, check)
}
