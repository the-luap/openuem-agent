package enrollcommand

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"io"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/keyfile"
)

func readProtectedInput(path string, limit int64) ([]byte, error) {
	file, err := keyfile.Open(path, limit)
	if err != nil {
		return nil, ErrOptions
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		clear(data)
		return nil, ErrOptions
	}
	return data, nil
}

func loadInvitation(path string) (string, error) {
	data, err := readProtectedInput(path, 64)
	if err != nil {
		return "", ErrInvitation
	}
	defer clear(data)
	trimmed := bytes.TrimSuffix(data, []byte("\r\n"))
	if len(trimmed) == len(data) {
		trimmed = bytes.TrimSuffix(data, []byte("\n"))
	}
	token := string(trimmed)
	if !enrollment.ValidToken(token) {
		return "", ErrInvitation
	}
	return token, nil
}

// Keys are public, but their origin and file integrity are trust decisions. Only
// a private installer-provisioned PEM file can authorize the release pipeline.
func loadReleaseKeys(path string) ([]ed25519.PublicKey, error) {
	data, err := readProtectedInput(path, 8192)
	if err != nil {
		return nil, ErrKeys
	}
	defer clear(data)
	var keys []ed25519.PublicKey
	seen := make(map[string]bool)
	for remaining := bytes.TrimSpace(data); len(remaining) != 0; {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN PUBLIC KEY-----")) {
			return nil, ErrKeys
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || bytes.Count(remaining[:len(remaining)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return nil, ErrKeys
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrKeys
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, ErrKeys
		}
		id := artifacts.KeyID(key)
		if id == "" || seen[id] || len(keys) >= 8 {
			return nil, ErrKeys
		}
		seen[id] = true
		keys = append(keys, append(ed25519.PublicKey(nil), key...))
		remaining = bytes.TrimSpace(rest)
	}
	if len(keys) == 0 {
		return nil, ErrKeys
	}
	return keys, nil
}
