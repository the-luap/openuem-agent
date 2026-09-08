package localready

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func fixtureIdentity() Identity {
	return Identity{DeviceID: "6f73f916-8aaf-4cd1-92e9-c8cbb11028ba", TenantID: 3, SiteID: 4, ReleaseDigest: strings.Repeat("a", 64), AgentSize: 42, AgentSHA256: strings.Repeat("b", 64), ExpiresAt: time.Now().Add(time.Hour).UTC()}
}

func fixtureKey(t *testing.T) (nkeys.KeyPair, string) {
	t.Helper()
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { key.Wipe() })
	return key, public
}

func TestReadinessProofBindsNonceIdentityAndNativePeerPID(t *testing.T) {
	for _, scenario := range []string{"ready", "initializing", "foreign-key", "foreign-scope", "foreign-image", "foreign-pid", "replay", "unknown-field", "wrong-domain", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			key, public := fixtureKey(t)
			identity := fixtureIdentity()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			server.SetDeadline(time.Now().Add(3 * time.Second))
			done := make(chan struct{})
			defer func() { client.Close(); server.Close(); <-done }()
			go func() {
				defer close(done)
				if scenario == "ready" || scenario == "initializing" {
					_ = reply(server, identity, key, 123, scenario == "ready")
					return
				}
				request := make([]byte, len(requestMagic)+32)
				if _, err := io.ReadFull(server, request); err != nil {
					return
				}
				got := response{Version: 1, Nonce: hex.EncodeToString(request[len(requestMagic):]), PID: 123, Ready: true, Identity: identity}
				domain := signatureDomain
				switch scenario {
				case "foreign-key":
					other, _ := nkeys.CreateUser()
					defer other.Wipe()
					key = other
				case "foreign-scope":
					got.Identity.SiteID++
				case "foreign-image":
					got.Identity.AgentSHA256 = strings.Repeat("c", 64)
				case "foreign-pid":
					got.PID++
				case "replay":
					got.Nonce = strings.Repeat("0", 64)
				case "wrong-domain":
					domain = "another.protocol\x00"
				case "oversize":
					var size [4]byte
					binary.BigEndian.PutUint32(size[:], maxResponse+1)
					server.Write(size[:])
					return
				}
				data, _ := json.Marshal(got)
				if scenario == "unknown-field" {
					data = append(data[:len(data)-1], []byte(`,"unexpected":true}`)...)
				}
				signature, _ := key.Sign(append([]byte(domain), data...))
				frame := make([]byte, 4)
				binary.BigEndian.PutUint32(frame, uint32(len(data)))
				server.Write(append(append(frame, data...), signature...))
			}()
			err := exchange(context.Background(), client, identity, public, 123)
			switch scenario {
			case "ready":
				if err != nil {
					t.Fatal(err)
				}
			case "initializing":
				if !errors.Is(err, ErrNotReady) {
					t.Fatal(err)
				}
			default:
				if !errors.Is(err, ErrConflict) {
					t.Fatal("unbound readiness was accepted", err)
				}
			}
		})
	}
}

func TestReadinessRejectsInvalidInputsBeforeWriting(t *testing.T) {
	_, public := fixtureKey(t)
	identity := fixtureIdentity()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var buffer bytes.Buffer
	if err := exchange(ctx, &buffer, identity, public, 123); !errors.Is(err, context.Canceled) || buffer.Len() != 0 {
		t.Fatal("canceled probe wrote a request", err)
	}
	identity.ExpiresAt = time.Now().Add(-time.Second)
	if err := exchange(context.Background(), &buffer, identity, public, 123); !errors.Is(err, ErrUnavailable) || buffer.Len() != 0 {
		t.Fatal("expired identity wrote a request", err)
	}
}
