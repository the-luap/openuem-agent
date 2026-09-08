// Package localready authenticates local individual-agent readiness. It never
// reports broker connectivity or accepts management/enrollment commands.
package localready

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nkeys"
)

var (
	ErrUnavailable = errors.New("the local agent readiness endpoint is unavailable")
	ErrConflict    = errors.New("the local readiness endpoint is occupied or does not match the protected identity")
	ErrNotReady    = errors.New("the individual agent has not completed local initialization")
)

const (
	requestMagic    = "OPENUEM-READY-1\n"
	signatureDomain = "openuem.local-readiness.v1\x00"
	maxResponse     = 2048
	exchangeTimeout = 2 * time.Second
)

// Identity contains public immutable metadata and the certificate deadline. The
// caller obtains it from validated native storage after executable admission.
type Identity struct {
	DeviceID      string    `json:"device_id"`
	TenantID      int       `json:"tenant_id"`
	SiteID        int       `json:"site_id"`
	ReleaseDigest string    `json:"release_digest"`
	AgentSize     int64     `json:"agent_size"`
	AgentSHA256   string    `json:"agent_sha256"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (i Identity) valid() bool {
	id, err := uuid.Parse(i.DeviceID)
	return err == nil && id.String() == i.DeviceID && i.TenantID > 0 && i.SiteID > 0 && i.AgentSize > 0 && i.AgentSize <= 512<<20 && digest(i.ReleaseDigest) && digest(i.AgentSHA256) && i.ExpiresAt.After(time.Now())
}

func digest(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 32 && hex.EncodeToString(data) == value
}

type response struct {
	Version  int      `json:"version"`
	Nonce    string   `json:"nonce"`
	PID      int      `json:"pid"`
	Ready    bool     `json:"ready"`
	Identity Identity `json:"identity"`
}

func reply(stream io.ReadWriter, identity Identity, signer nkeys.KeyPair, pid int, ready bool) error {
	identity.ExpiresAt = identity.ExpiresAt.UTC()
	request := make([]byte, len(requestMagic)+32)
	if _, err := io.ReadFull(stream, request); err != nil || string(request[:len(requestMagic)]) != requestMagic || !identity.valid() || pid <= 0 {
		return ErrUnavailable
	}
	data, err := json.Marshal(response{Version: 1, Nonce: hex.EncodeToString(request[len(requestMagic):]), PID: pid, Ready: ready, Identity: identity})
	if err != nil || len(data) > maxResponse {
		return ErrUnavailable
	}
	signature, err := signer.Sign(append([]byte(signatureDomain), data...))
	if err != nil || len(signature) != 64 {
		return ErrUnavailable
	}
	frame := make([]byte, 4, 4+len(data)+len(signature))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	frame = append(frame, data...)
	frame = append(frame, signature...)
	if n, err := stream.Write(frame); err != nil || n != len(frame) {
		return ErrUnavailable
	}
	return nil
}

func exchange(ctx context.Context, stream io.ReadWriter, identity Identity, publicKey string, pid int) error {
	identity.ExpiresAt = identity.ExpiresAt.UTC()
	if ctx == nil || !identity.valid() || pid <= 0 {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	verifier, err := nkeys.FromPublicKey(publicKey)
	if err != nil || !nkeys.IsValidPublicUserKey(publicKey) {
		return ErrUnavailable
	}
	defer verifier.Wipe()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return ErrUnavailable
	}
	request := append([]byte(requestMagic), nonce...)
	if n, err := stream.Write(request); err != nil || n != len(request) {
		return ErrUnavailable
	}
	var length [4]byte
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		return ErrUnavailable
	}
	size := binary.BigEndian.Uint32(length[:])
	if size < 1 || size > maxResponse {
		return ErrConflict
	}
	frame := make([]byte, int(size)+64)
	if _, err := io.ReadFull(stream, frame); err != nil {
		return ErrUnavailable
	}
	data, signature := frame[:size], frame[size:]
	if verifier.Verify(append([]byte(signatureDomain), data...), signature) != nil {
		return ErrConflict
	}
	var got response
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&got) != nil {
		return ErrConflict
	}
	canonical, err := json.Marshal(got)
	if err != nil || !bytes.Equal(data, canonical) || got.Version != 1 || got.Nonce != hex.EncodeToString(nonce) || got.PID != pid || got.Identity != identity || !got.Identity.valid() {
		return ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !got.Ready {
		return ErrNotReady
	}
	return nil
}
