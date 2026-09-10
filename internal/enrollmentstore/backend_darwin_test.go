//go:build darwin && cgo && openuem_keychain_test

package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

type keychainFixture struct {
	keychain           *temporaryKeychain
	backend            *keychainBackend
	directory, service string
	password           []byte
}

func TestMacKeychainDurableEnrollmentRecovery(t *testing.T) {
	f := newKeychainFixture(t)
	runDurableEnrollmentRecovery(t, f.backend)
}

func TestMacKeychainDurableRecoveryRecipient(t *testing.T) {
	f := newKeychainFixture(t)
	runDurableRecipient(t, f.backend)
}

func TestMacKeychainDurableRotationJournal(t *testing.T) {
	f := newKeychainFixture(t)
	runDurableRotationJournal(t, f.backend)
}

func newKeychainFixture(t *testing.T) *keychainFixture {
	t.Helper()
	directory := t.TempDir()
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	password := []byte(hex.EncodeToString(random))
	clear(random)
	k, err := createTemporaryKeychain(filepath.Join(directory, "openuem-fixture.keychain"), password)
	if err != nil {
		clear(password)
		t.Fatal("could not create the isolated noninteractive keychain", err)
	}
	t.Cleanup(func() {
		if err := k.Unlock(password); err != nil {
			t.Error("could not unlock isolated keychain for cleanup", err)
		}
		if err := k.Delete(); err != nil {
			t.Error("could not delete isolated keychain", err)
		}
		clear(password)
	})
	service := "org.openuem.test.enrollment." + uuid.NewString()
	b, err := openFileKeychain(k.path, service)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return &keychainFixture{keychain: k, backend: b, directory: directory, service: service, password: password}
}

func TestMacKeychainStorageIsPrivateImmutableAndRecoverable(t *testing.T) {
	f := newKeychainFixture(t)
	secret := []byte("isolated-keychain-private-record-" + uuid.NewString())
	if _, err := f.backend.Load(pendingRecord); !errors.Is(err, ErrMissing) {
		t.Fatal("empty keychain returned a record", err)
	}
	if err := f.backend.Create(pendingRecord, secret); err != nil {
		t.Fatal(err)
	}
	if err := f.backend.Create(pendingRecord, []byte("replacement")); !errors.Is(err, ErrExists) {
		t.Fatal("keychain replaced an existing record", err)
	}
	if err := f.backend.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.backend.Load(pendingRecord); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed backend returned state", err)
	}
	restarted, err := openFileKeychain(f.keychain.path, f.service)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	data, err := restarted.Load(pendingRecord)
	if err != nil || !bytes.Equal(data, secret) {
		t.Fatal("reopened keychain did not recover state", err)
	}
	clear(data)
	other, err := openFileKeychain(f.keychain.path, f.service+".other")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.Load(pendingRecord); !errors.Is(err, ErrMissing) {
		t.Fatal("keychain namespace crossed installation boundaries", err)
	}
	if _, err = restarted.Load(identityRecord); !errors.Is(err, ErrMissing) {
		t.Fatal("pending record appeared as a completed identity", err)
	}
	for _, name := range []string{"", "../identity", "PENDING"} {
		if err = restarted.Create(name, secret); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid record accepted", err)
		}
	}
	for _, record := range [][]byte{nil, make([]byte, maxRecordSize+1)} {
		if err = restarted.Create(identityRecord, record); !errors.Is(err, ErrUnavailable) {
			t.Fatal("unbounded keychain record accepted", err)
		}
	}
	// Inspect only files in this test's own temporary keychain directory.
	files, err := os.ReadDir(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(f.directory, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, secret) {
			t.Fatal("private keychain payload appeared in plaintext on disk")
		}
		clear(data)
	}
}

func TestMacKeychainPartialRestoreCannotReplaceLaterJournalEvidence(t *testing.T) {
	f := newKeychainFixture(t)
	runRetainedSecurityPreventsEnrollment(t, f.backend, rotationRecord(true, enrollment.MaxRotationAttempts), restorePendingFixture(t))
}

func TestMacKeychainDurableIdentityRenewal(t *testing.T) {
	f := newKeychainFixture(t)
	runDurableIdentityRenewal(t, f.backend)
}

func TestMacKeychainDurableIdentityRenewalResolution(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "confirmed"}[confirmed], func(t *testing.T) {
			f := newKeychainFixture(t)
			runDurableIdentityRenewalResolution(t, f.backend, confirmed)
		})
	}
}

func TestMacLockedKeychainFailsWithoutPromptOrReplacement(t *testing.T) {
	f := newKeychainFixture(t)
	if err := f.backend.Create(pendingRecord, []byte("locked fixture")); err != nil {
		t.Fatal(err)
	}
	if err := f.keychain.Lock(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.backend.Load(pendingRecord); !errors.Is(err, ErrUnavailable) {
		t.Fatal("locked keychain was treated as missing or readable", err)
	}
	if err := f.backend.Create(identityRecord, []byte("must not create")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("locked keychain admitted new state", err)
	}
	if _, err := openFileKeychain(f.keychain.path, f.service); !errors.Is(err, ErrUnavailable) {
		t.Fatal("locked keychain was reopened as an empty store", err)
	}
	if err := f.keychain.Unlock(f.password); err != nil {
		t.Fatal(err)
	}
	data, err := f.backend.Load(pendingRecord)
	if err != nil || string(data) != "locked fixture" {
		t.Fatal("unlock lost the original record", err)
	}
	clear(data)
}

func TestMacConcurrentPublicationHasOneCompleteWinner(t *testing.T) {
	f := newKeychainFixture(t)
	var work sync.WaitGroup
	defer work.Wait()
	results := make(chan error, 8)
	// Separate handles exercise the keychain's exclusive item creation, not just
	// the mutex that protects one backend's Core Foundation reference.
	for i := 0; i < 8; i++ {
		b, err := openFileKeychain(f.keychain.path, f.service)
		if err != nil {
			t.Fatal(err)
		}
		work.Go(func() { defer b.Close(); results <- b.Create(pendingRecord, bytes.Repeat([]byte{byte(i + 1)}, 8192)) })
	}
	work.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrExists) {
			t.Fatal("concurrent keychain publication failed", err)
		}
	}
	if winners != 1 {
		t.Fatal("keychain had more than one winning record", winners)
	}
	data, err := f.backend.Load(pendingRecord)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if len(data) != 8192 || data[0] < 1 || data[0] > 8 || !bytes.Equal(data, bytes.Repeat(data[:1], len(data))) {
		t.Fatal("keychain published an incomplete or mixed record")
	}
}

func TestMacKeychainSeparateProcessRecovery(t *testing.T) {
	f := newKeychainFixture(t)
	secret := make([]byte, maxRecordSize)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	if err := f.backend.Create(pendingRecord, secret); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(secret)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestMacKeychainProcessFixture$")
	command.Env = append(os.Environ(), "OPENUEM_TEST_KEYCHAIN="+f.keychain.path,
		"OPENUEM_TEST_KEYCHAIN_SERVICE="+f.service,
		"OPENUEM_TEST_KEYCHAIN_DIGEST="+hex.EncodeToString(digest[:]))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("separate keychain process failed: %v\n%s", err, output)
	}
	data, err := f.backend.Load(identityRecord)
	if err != nil || string(data) != "separate process fixture" {
		t.Fatal("parent could not recover child publication", err)
	}
	clear(data)
}

func TestMacKeychainProcessFixture(t *testing.T) {
	path := os.Getenv("OPENUEM_TEST_KEYCHAIN")
	if path == "" {
		t.Skip("helper runs only in the isolated fixture process")
	}
	if filepath.Base(path) != "openuem-fixture.keychain" {
		t.Fatal("invalid fixture path")
	}
	b, err := openFileKeychain(path, os.Getenv("OPENUEM_TEST_KEYCHAIN_SERVICE"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	data, err := b.Load(pendingRecord)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	digest := sha256.Sum256(data)
	if len(data) != maxRecordSize || hex.EncodeToString(digest[:]) != os.Getenv("OPENUEM_TEST_KEYCHAIN_DIGEST") {
		t.Fatal("separate process recovered different state")
	}
	if err := b.Create(identityRecord, []byte("separate process fixture")); err != nil {
		t.Fatal(err)
	}
}
