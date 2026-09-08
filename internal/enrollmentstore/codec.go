package enrollmentstore

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

const (
	pendingMagic  = "openuem/enrollment/pending/v1\x00"
	identityMagic = "openuem/enrollment/identity/v1\x00"
)

// These private codecs are only called at the protected storage boundary. The
// protocol's Keys.MarshalJSON remains forbidden. DER and seed buffers never go
// into HTTP payloads, command arguments, configuration files or diagnostics.
func encodePending(bootstrap Bootstrap, keys *enrollment.Keys) ([]byte, error) {
	if !bootstrap.valid() || keys == nil || keys.Certificate == nil || keys.Broker == nil {
		return nil, ErrUnavailable
	}
	config, err := json.Marshal(bootstrap)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(config)
	der, err := x509.MarshalPKCS8PrivateKey(keys.Certificate)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(der)
	borrowed, err := keys.Broker.Seed()
	if err != nil {
		return nil, ErrUnavailable
	}
	// Seed can alias a live keypair. Only clear our own copy.
	seed := bytes.Clone(borrowed)
	defer clear(seed)
	return encodeFields(pendingMagic, config, der, seed)
}

func decodePending(data []byte) (*pending, error) {
	fields, err := decodeFields(data, pendingMagic, 3)
	if err != nil || len(fields[0]) > 4096 || len(fields[1]) > 8192 || len(fields[2]) > 128 {
		return nil, ErrUnavailable
	}
	var config Bootstrap
	if err = decodeCanonicalJSON(fields[0], &config); err != nil || !config.valid() {
		return nil, ErrUnavailable
	}
	parsed, err := x509.ParsePKCS8PrivateKey(fields[1])
	if err != nil {
		return nil, ErrUnavailable
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N == nil || key.N.BitLen() < 3072 || key.N.BitLen() > 4096 || key.E != 65537 || len(key.Primes) != 2 || key.Validate() != nil {
		return nil, ErrUnavailable
	}
	broker, err := nkeys.FromSeed(fields[2])
	if err != nil {
		return nil, ErrUnavailable
	}
	public, err := broker.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		broker.Wipe()
		return nil, ErrUnavailable
	}
	return &pending{bootstrap: config, keys: &enrollment.Keys{Certificate: key, Broker: broker}, digest: sha256.Sum256(data)}, nil
}

func encodeIdentity(digest [sha256.Size]byte, response enrollment.Response) ([]byte, error) {
	data, err := json.Marshal(response)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(data)
	return encodeFields(identityMagic, digest[:], data)
}

func decodeIdentity(data []byte, digest [sha256.Size]byte) (enrollment.Response, error) {
	var response enrollment.Response
	fields, err := decodeFields(data, identityMagic, 2)
	if err != nil || !bytes.Equal(fields[0], digest[:]) || decodeCanonicalJSON(fields[1], &response) != nil {
		return response, ErrUnavailable
	}
	return response, nil
}

func encodeFields(magic string, fields ...[]byte) ([]byte, error) {
	size := len(magic)
	for _, field := range fields {
		if len(field) == 0 || len(field) > maxRecordSize || size > maxRecordSize-4-len(field) {
			return nil, ErrUnavailable
		}
		size += 4 + len(field)
	}
	data := make([]byte, 0, size)
	data = append(data, magic...)
	for _, field := range fields {
		data = binary.BigEndian.AppendUint32(data, uint32(len(field)))
		data = append(data, field...)
	}
	return data, nil
}

func decodeFields(data []byte, magic string, count int) ([][]byte, error) {
	if len(data) > maxRecordSize || !bytes.HasPrefix(data, []byte(magic)) {
		return nil, ErrUnavailable
	}
	rest := data[len(magic):]
	fields := make([][]byte, 0, count)
	for range count {
		if len(rest) < 4 {
			return nil, ErrUnavailable
		}
		size := binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
		if size == 0 || uint64(size) > uint64(len(rest)) {
			return nil, ErrUnavailable
		}
		fields = append(fields, rest[:int(size)])
		rest = rest[int(size):]
	}
	if len(rest) != 0 {
		return nil, ErrUnavailable
	}
	return fields, nil
}

func decodeCanonicalJSON(data []byte, target any) error {
	if err := json.Unmarshal(data, target); err != nil {
		return ErrUnavailable
	}
	canonical, err := json.Marshal(target)
	defer clear(canonical)
	if err != nil || !bytes.Equal(data, canonical) {
		return ErrUnavailable
	}
	return nil
}
