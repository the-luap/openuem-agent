package enrollmentstore

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/open-uem/nats/enrollment"
)

const recipientMagic = "openuem/enrollment/recipient/v1\x00"

// LoadOrCreateRecipient leaves the v1 pending and identity records unchanged.
// The separate immutable record binds the key to that installation, device and
// scope. Only a durable winning record may be registered with the service.
func (s *Store) LoadOrCreateRecipient(expected *Identity) (*enrollment.RecoveryRecipientKey, error) {
	if s == nil || expected == nil || expected.Keys == nil || expected.Keys.Certificate == nil || expected.Platform != "macos" {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backend == nil {
		return nil, ErrUnavailable
	}
	p, err := s.loadPending()
	if err != nil {
		return nil, ErrUnavailable
	}
	defer p.close()
	current, err := s.loadIdentity(p)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer current.Close()
	if current.Response != expected.Response || current.Origin != expected.Origin || current.Platform != expected.Platform ||
		!current.Keys.Certificate.PublicKey.Equal(&expected.Keys.Certificate.PublicKey) {
		return nil, ErrUnavailable
	}
	// Do not bind to certificate DER: a future authenticated renewal can retain
	// this recipient while still requiring a new server registration epoch.
	binding, err := json.Marshal(struct {
		Origin   string `json:"origin"`
		DeviceID string `json:"device_id"`
		TenantID int    `json:"tenant_id"`
		SiteID   int    `json:"site_id"`
	}{current.Origin, current.Response.DeviceID, current.Response.TenantID, current.Response.SiteID})
	if err != nil {
		return nil, ErrUnavailable
	}
	data, err := s.backend.Load(recipientRecord)
	if errors.Is(err, ErrMissing) {
		key, generateErr := enrollment.NewRecoveryRecipientKey()
		if generateErr != nil {
			return nil, ErrUnavailable
		}
		private, encodeErr := key.Bytes()
		key.Close()
		if encodeErr != nil {
			return nil, ErrUnavailable
		}
		encoded, encodeErr := encodeFields(recipientMagic, p.digest[:], binding, private)
		clear(private)
		if encodeErr != nil {
			return nil, ErrUnavailable
		}
		err = s.backend.Create(recipientRecord, encoded)
		clear(encoded)
		if err != nil && !errors.Is(err, ErrExists) {
			return nil, ErrUnavailable
		}
		data, err = s.backend.Load(recipientRecord)
	}
	defer clear(data)
	if err != nil {
		return nil, ErrUnavailable
	}
	fields, err := decodeFields(data, recipientMagic, 3)
	if err != nil || !bytes.Equal(fields[0], p.digest[:]) || !bytes.Equal(fields[1], binding) {
		return nil, ErrUnavailable
	}
	key, err := enrollment.ParseRecoveryRecipientKey(fields[2])
	if err != nil {
		return nil, ErrUnavailable
	}
	return key, nil
}
