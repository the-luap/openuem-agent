package enrollmentstore

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/open-uem/nats/enrollment"
)

func recipientFixture(t *testing.T, backend NativeBackend) (*Store, *Identity) {
	t.Helper()
	s := &Store{backend: backend}
	b := testBootstrap()
	b.Platform = "macos"
	issuer := newFixtureIssuer(t)
	i, err := s.enroll(context.Background(), b, func(_ context.Context, r enrollment.Request) (*enrollment.Response, error) {
		return issuer.claim(b.Origin, r)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { i.Close() })
	return s, i
}

func runDurableRecipient(t *testing.T, backend NativeBackend) {
	t.Helper()
	s, i := recipientFixture(t, backend)
	beforePending, _ := backend.Load(pendingRecord)
	beforeIdentity, _ := backend.Load(identityRecord)
	defer clear(beforePending)
	defer clear(beforeIdentity)
	type result struct {
		key *enrollment.RecoveryRecipientKey
		err error
	}
	results := make(chan result, 4)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other := &Store{backend: backend}
			key, err := other.LoadOrCreateRecipient(i)
			results <- result{key, err}
		}()
	}
	wg.Wait()
	close(results)
	var public []byte
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if public != nil && !bytes.Equal(public, r.key.PublicKey()) {
			t.Fatal("racing stores registered different recipients")
		}
		public = r.key.PublicKey()
		r.key.Close()
	}
	loaded, err := s.Load()
	if err != nil {
		t.Fatal("existing identity changed", err)
	}
	defer loaded.Close()
	key, err := s.LoadOrCreateRecipient(loaded)
	if err != nil || !bytes.Equal(public, key.PublicKey()) {
		t.Fatal("recipient did not survive identity reload", err)
	}
	defer key.Close()
	for name, before := range map[string][]byte{pendingRecord: beforePending, identityRecord: beforeIdentity} {
		after, err := backend.Load(name)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("existing record was rewritten", name)
		}
		clear(after)
	}
}

func TestRecoveryRecipientPersistsAcrossConcurrentStarts(t *testing.T) {
	runDurableRecipient(t, newMemoryBackend(t))
}

func TestRecoveryRecipientRejectsCorruptionAndForeignBinding(t *testing.T) {
	b := newMemoryBackend(t)
	s, i := recipientFixture(t, b)
	k, err := s.LoadOrCreateRecipient(i)
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
	original := bytes.Clone(b.records[recipientRecord])
	defer clear(original)
	fields, err := decodeFields(original, recipientMagic, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{
		[]byte("broken record"), append(bytes.Clone(original), 0), original[:len(original)-1],
	} {
		b.records[recipientRecord] = bytes.Clone(value)
		if _, err = s.LoadOrCreateRecipient(i); !errors.Is(err, ErrUnavailable) {
			t.Fatal("corrupt recipient silently replaced", err)
		}
	}
	for index := range 2 {
		changed := bytes.Clone(fields[index])
		changed[0] ^= 1
		parts := [][]byte{fields[0], fields[1], fields[2]}
		parts[index] = changed
		b.records[recipientRecord], _ = encodeFields(recipientMagic, parts...)
		if _, err = s.LoadOrCreateRecipient(i); !errors.Is(err, ErrUnavailable) {
			t.Fatal("foreign recipient binding accepted", err)
		}
	}
	b.records[recipientRecord] = bytes.Clone(original)
	wrong := *i
	wrong.Response.SiteID++
	if _, err = s.LoadOrCreateRecipient(&wrong); !errors.Is(err, ErrUnavailable) {
		t.Fatal("detached foreign scope accepted", err)
	}
	delete(b.records, pendingRecord)
	delete(b.records, identityRecord)
	if _, err = s.Load(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("orphan recipient allowed fresh enrollment", err)
	}
}

func TestRecoveryRecipientLostCommitResponseReloadsDurableWinner(t *testing.T) {
	b := newMemoryBackend(t)
	s, i := recipientFixture(t, b)
	b.failCreate, b.commitBeforeError = recipientRecord, true
	if _, err := s.LoadOrCreateRecipient(i); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unacknowledged publication succeeded", err)
	}
	stored := bytes.Clone(b.records[recipientRecord])
	defer clear(stored)
	b.failCreate = ""
	k, err := s.LoadOrCreateRecipient(i)
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
	if !bytes.Equal(stored, b.records[recipientRecord]) {
		t.Fatal("lost commit generated replacement recipient")
	}
}
