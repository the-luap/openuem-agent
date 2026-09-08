package enrollcommand

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestInvitationInputIsPrivateBoundedAndCanonical(t *testing.T) {
	f := newCommandFixture(t)
	for _, suffix := range []string{"", "\n", "\r\n"} {
		path := filepath.Join(t.TempDir(), "invitation")
		if err := keyfile.Create(path, []byte(f.config.Invitation+suffix)); err != nil {
			t.Fatal(err)
		}
		if token, err := loadInvitation(path); err != nil || token != f.config.Invitation {
			t.Fatal("valid limited invitation rejected", err)
		}
	}
	for _, input := range []string{" " + f.config.Invitation, f.config.Invitation + "\n\n", f.config.Invitation + "=", "https://example.test/" + f.config.Invitation, string(bytes.Repeat([]byte{'a'}, 65))} {
		path := filepath.Join(t.TempDir(), "invitation")
		if err := keyfile.Create(path, []byte(input)); err != nil {
			t.Fatal(err)
		}
		if token, err := loadInvitation(path); token != "" || !errors.Is(err, ErrInvitation) {
			t.Fatal("noncanonical invitation accepted")
		}
	}
	alias := filepath.Join(filepath.Dir(f.options.InvitationFile), "alias")
	if err := os.Symlink(f.options.InvitationFile, alias); err == nil {
		if _, err := loadInvitation(alias); !errors.Is(err, ErrInvitation) {
			t.Fatal("invitation alias accepted")
		}
	}
}

func TestReleasePinsRejectPrivateDuplicateSkippedAndExcessivePEMInput(t *testing.T) {
	f := newCommandFixture(t)
	publicPEM, err := os.ReadFile(f.options.ReleaseKeysFile)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(f.releaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateDER)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	defer clear(privatePEM)
	tooMany := []byte{}
	for i := 0; i < 9; i++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		clear(private)
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		tooMany = append(tooMany, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...)
	}
	for _, input := range [][]byte{
		privatePEM,
		append(bytes.Clone(publicPEM), publicPEM...),
		append([]byte("untrusted preamble\n"), publicPEM...),
		append([]byte("-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n"), publicPEM...),
		append(bytes.Clone(publicPEM), []byte("trailing data")...),
		tooMany,
		bytes.Repeat([]byte{'a'}, 8193),
	} {
		path := filepath.Join(t.TempDir(), "release.pem")
		if err := keyfile.Create(path, input); err != nil {
			t.Fatal(err)
		}
		if keys, err := loadReleaseKeys(path); keys != nil || !errors.Is(err, ErrKeys) {
			t.Fatal("invalid independent release keys accepted")
		}
	}
	keys, err := loadReleaseKeys(f.options.ReleaseKeysFile)
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0], f.releaseKey.Public().(ed25519.PublicKey)) {
		t.Fatal("provisioned release key rejected", err)
	}
}
