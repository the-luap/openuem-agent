package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
)

func TestInstallationBindingRequiresCompletedEnrollmentAndReturnsOnlyPublicMetadata(t *testing.T) {
	b := newMemoryBackend(t)
	s := &Store{backend: b}
	if binding, err := s.InstallationBinding(); binding != nil || !errors.Is(err, ErrMissing) {
		t.Fatal("empty store provided installation authority", err)
	}
	bootstrap := testBootstrap()
	bootstrap.AgentSize, bootstrap.AgentSHA256 = 1234, strings.Repeat("a", 64)
	bootstrap.ReleaseSequence = 47
	_, err := s.enroll(t.Context(), bootstrap, func(context.Context, enrollment.Request) (*enrollment.Response, error) { return nil, context.Canceled })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if binding, err := s.InstallationBinding(); binding != nil || !errors.Is(err, ErrPending) {
		t.Fatal("pending enrollment provided service binding", err)
	}
	issuer := newFixtureIssuer(t)
	i, err := s.enroll(t.Context(), bootstrap, func(_ context.Context, q enrollment.Request) (*enrollment.Response, error) {
		return issuer.claim(bootstrap.Origin, q)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	binding, err := s.InstallationBinding()
	if err != nil || !binding.Matches(i) || binding.ReleaseSequence != 47 || binding.AgentSize != 1234 || binding.AgentSHA256 != bootstrap.AgentSHA256 {
		t.Fatal("binding lost protected installation metadata", err)
	}
	wire, err := json.Marshal(binding)
	if err != nil || bytes.Contains(wire, []byte(bootstrap.Invitation)) || bytes.Contains(wire, []byte("PRIVATE KEY")) || bytes.Contains(wire, []byte(i.Response.Certificate)) {
		t.Fatal("public service binding exposed credentials", err)
	}
	for _, change := range []func(*InstallationBinding){
		func(b *InstallationBinding) { b.DeviceID = "other" }, func(b *InstallationBinding) { b.TenantID++ }, func(b *InstallationBinding) { b.SiteID++ }, func(b *InstallationBinding) { b.Origin = "https://other.example.test" }, func(b *InstallationBinding) { b.Platform = "macos" }, func(b *InstallationBinding) { b.Architecture = "arm64" }, func(b *InstallationBinding) { b.ReleaseDigest = strings.Repeat("c", 64) }, func(b *InstallationBinding) { b.ReleaseSequence++ }, func(b *InstallationBinding) { b.AgentSize++ }, func(b *InstallationBinding) { b.AgentSHA256 = strings.Repeat("b", 64) },
	} {
		modified := *binding
		change(&modified)
		if modified.Matches(i) {
			t.Fatal("binding accepted a different installation")
		}
	}
	if binding.Matches(nil) {
		t.Fatal("binding matched absent identity")
	}
	if _, err := i.Keys.Broker.Sign([]byte("binding read does not release caller-owned keys")); err != nil {
		t.Fatal(err)
	}
	if again, err := s.InstallationBinding(); err != nil || !reflect.DeepEqual(again, binding) {
		t.Fatal("metadata copy changed durable state", err)
	}
}

func TestInstallationBindingRemainsReadableAcrossUncertainRenewalAndExpiryWithoutReleasingKeys(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "confirmed"}[confirmed], func(t *testing.T) {
			f := newRenewalFixture(t, newMemoryBackend(t), "windows")
			before, err := f.store.InstallationBinding()
			if err != nil {
				t.Fatal(err)
			}
			id := f.uncertainRenewal(t, confirmed)
			if after, err := f.restarted().InstallationBinding(); err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("uncertainty prevented executable preflight", err)
			}
			if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrRenewalHandoff) {
				t.Fatal("metadata read authorized old keys", err)
			}
			identity, err := f.store.resolveRenewal(t.Context(), id, f.resolve)
			if err != nil {
				t.Fatal(err)
			}
			defer identity.Close()
			if after, err := f.restarted().InstallationBinding(); err != nil || !reflect.DeepEqual(before, after) || !after.Matches(identity) {
				t.Fatal("resolution changed installation authority", err)
			}
			f.now = identity.Response.ExpiresAt.Add(time.Second)
			if after, err := f.restarted().InstallationBinding(); err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("expiry erased executable preflight evidence", err)
			}
			if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("metadata read revived expired credentials", err)
			}
		})
	}
}

func TestInstallationBindingRejectsCorruptHistoryAndPartialRestores(t *testing.T) {
	b := newMemoryBackend(t)
	f := newRenewalFixture(t, b, "windows")
	id := f.uncertainRenewal(t, true)
	identity, err := f.store.resolveRenewal(t.Context(), id, f.resolve)
	if err != nil {
		t.Fatal(err)
	}
	identity.Close()
	for _, name := range []string{pendingRecord, identityRecord, renewalRecord("candidate", 1), renewalRecord("issued", 1), renewalRecord("decision", 1), renewalRecord("resolved", 1)} {
		original, err := b.Load(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, corrupt := range []bool{false, true} {
			b.mu.Lock()
			if corrupt {
				b.records[name] = append(bytes.Clone(original), 0)
			} else {
				delete(b.records, name)
			}
			b.mu.Unlock()
			binding, err := f.restarted().InstallationBinding()
			if !corrupt && name == renewalRecord("resolved", 1) {
				// Losing only the final reply leaves an authentic installation in
				// quarantine. Its public executable binding is still safe to inspect.
				if err != nil || binding == nil {
					t.Fatal("quarantined installation lost preflight", err)
				}
				if identity, err := f.restarted().Load(); identity != nil || !errors.Is(err, ErrRenewalHandoff) {
					t.Fatal("preflight released quarantined keys", err)
				}
			} else if binding != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("corrupt history supplied service binding", name, err)
			}
			b.mu.Lock()
			b.records[name] = bytes.Clone(original)
			b.mu.Unlock()
		}
		clear(original)
	}
}
