package enrollmentstore

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/bootstrap"
)

// EnrollVerified connects an independently verified signed configuration to
// durable pending state. The caller must authorize its origin/signing keys and
// complete native package/signature verification before invoking this method.
// The durable checkpoint is rechecked here; a concurrent different bootstrap
// still loses exclusive pending publication and cannot send a replacement claim.
func (s *Store) EnrollVerified(ctx context.Context, verified *bootstrap.Verified, deviceName string, roots *x509.CertPool) (*Identity, error) {
	if verified == nil {
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
	if err := verified.ValidAt(time.Now(), checkpoint); err != nil {
		return nil, err
	}
	b.ReleaseSequence = verified.Checkpoint().Sequence
	client, err := enrollment.NewHTTPClient(b.Origin, roots)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer client.CloseIdleConnections()
	return s.enroll(ctx, b, func(ctx context.Context, request enrollment.Request) (*enrollment.Response, error) {
		// Key generation and HTTPS can cross the signed expiry boundary. Recheck
		// both before the claim and before allowing its result to be published.
		if err := verified.ValidAt(time.Now(), checkpoint); err != nil {
			return nil, err
		}
		response, err := client.Claim(ctx, request)
		if err != nil {
			return nil, err
		}
		if err := verified.ValidAt(time.Now(), checkpoint); err != nil {
			return nil, err
		}
		return response, nil
	})
}
