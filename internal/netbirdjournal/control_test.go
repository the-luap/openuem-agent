package netbirdjournal

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
)

func controlRequest(c netbirdcommand.Command, kind string) netbirdcommand.ControlRequest {
	now := time.Now().UTC()
	r := netbirdcommand.ControlRequest{Version: 1, Identity: c.Identity, RequestID: uuid.NewString(), Kind: kind, IssuedAt: now, ExpiresAt: now.Add(netbirdcommand.ControlLifetime)}
	if kind != "state" {
		r.ReferenceID, r.CommandHash = c.RequestID, mustDigest(c)
	}
	return r
}

func mustDigest(c netbirdcommand.Command) string { hash, _ := c.Digest(); return hash }

func runControl(t *testing.T, j *Journal, c netbirdcommand.ControlRequest) netbirdcommand.ControlResponse {
	t.Helper()
	data, err := netbirdcommand.EncodeControl(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := j.Control(context.Background(), data)
	if err != nil || !r.Matches(c) {
		t.Fatal("control did not return correlated evidence", err)
	}
	encoded, err := netbirdcommand.EncodeControlResponse(c, r)
	if err != nil {
		t.Fatal(err)
	}
	r, err = netbirdcommand.DecodeControlResponse(encoded, c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestControlStateTransitionsAndLostReleaseResponse(t *testing.T) {
	c := testCommand()
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	initial := runControl(t, j, controlRequest(c, "state")).State
	if initial.Status != "ready" || initial.Remaining != MaxAttempts || !initial.Valid() {
		t.Fatal("fresh journal unavailable", initial)
	}
	if again := j.State(c.IssuedAt.Add(time.Second)); again != initial {
		t.Fatal("read-only query changed revision")
	}
	if r := runControl(t, j, controlRequest(c, "receipt")); r.Outcome != "missing" {
		t.Fatal("invented receipt")
	}
	beginTest(t, j, c)
	busy := runControl(t, j, controlRequest(c, "state")).State
	if busy.Status != "busy" || busy.CanRelease || busy.Remaining != MaxAttempts-1 || busy.PendingID != c.RequestID || busy.Revision == initial.Revision {
		t.Fatal("active attempt not reflected", busy)
	}
	release := controlRequest(c, "release")
	if r := runControl(t, j, release); r.Outcome != "blocked" {
		t.Fatal("live command released")
	}
	if _, err := j.Finish(c, "unconfirmed", time.Now()); err != nil {
		t.Fatal(err)
	}
	uncertain := runControl(t, j, controlRequest(c, "state")).State
	if uncertain.Status != "unconfirmed" || !uncertain.CanRelease || uncertain.Revision == busy.Revision {
		t.Fatal("joined uncertainty not reflected", uncertain)
	}
	// Discard the release reply and close the entire owner before querying it.
	if r := runControl(t, j, release); r.Outcome != "ok" {
		t.Fatal("explicit release failed")
	}
	j.Close()
	j = openTest(t, path, c, testBoot())
	r := runControl(t, j, controlRequest(c, "receipt"))
	if r.Outcome != "ok" || r.ReleaseID != release.RequestID || r.Receipt.Status != "unconfirmed" {
		t.Fatal("lost release response lost permanent evidence")
	}
	if r := runControl(t, j, release); r.Outcome != "ok" {
		t.Fatal("release replay not idempotent")
	}
	if r := runControl(t, j, controlRequest(c, "release")); r.Outcome != "conflict" {
		t.Fatal("release identity replaced")
	}
	ready := runControl(t, j, controlRequest(c, "state")).State
	if ready.Status != "ready" || ready.Remaining != MaxAttempts-1 || ready.Revision == uncertain.Revision || ready.Revision == initial.Revision {
		t.Fatal("released journal lost history", ready)
	}
	next := c
	next.RequestID = uuid.NewString()
	beginTest(t, j, next)
	if _, err := j.Finish(next, "completed", time.Now()); err != nil {
		t.Fatal(err)
	}
	if r := runControl(t, j, controlRequest(next, "release")); r.Outcome != "blocked" {
		t.Fatal("completed command was releasable")
	}
}

func TestControlRecoveryAndCurrentCertificate(t *testing.T) {
	c := testCommand()
	c.Identity = netbirdcommand.Identity{DeviceID: uuid.NewString(), TenantID: 1, SiteID: 2, Individual: true, CertificateHash: strings.Repeat("c", 64)}
	path := filepath.Join(t.TempDir(), "journal")
	j := openTest(t, path, c, testBoot())
	initial := j.State(time.Now())
	beginTest(t, j, c)
	j.Close()
	current := c
	current.CertificateHash = strings.Repeat("d", 64)
	j = openTest(t, path, current, testBoot())
	state := runControl(t, j, controlRequest(current, "state")).State
	if state.Status != "unconfirmed" || state.CanRelease || state.Revision == initial.Revision {
		t.Fatal("same-boot recovery allowed release")
	}
	if r := runControl(t, j, controlRequest(current, "release")); r.Outcome != "conflict" {
		t.Fatal("current command hash replaced old command")
	}
	query := controlRequest(current, "receipt")
	query.CommandHash = mustDigest(c)
	if r := runControl(t, j, query); r.Outcome != "ok" || !r.Receipt.Matches(c) {
		t.Fatal("renewal lost historical evidence")
	}
	old, _ := netbirdcommand.EncodeControl(controlRequest(c, "receipt"))
	if _, err := j.Control(context.Background(), old); err == nil {
		t.Fatal("old identity authorized query")
	}
	j.Close()
	boot := testBoot()
	boot.ID = uuid.NewString()
	j = openTest(t, path, current, boot)
	state = runControl(t, j, controlRequest(current, "state")).State
	if state.Status != "unconfirmed" || !state.CanRelease {
		t.Fatal("later boot did not permit explicit review")
	}
	release := controlRequest(current, "release")
	release.CommandHash = mustDigest(c)
	if r := runControl(t, j, release); r.Outcome != "ok" || r.Receipt.Status != "unconfirmed" {
		t.Fatal("recovery release failed")
	}
}

func TestControlRejectsExpiryCancellationAndTampering(t *testing.T) {
	c := testCommand()
	j := openTest(t, filepath.Join(t.TempDir(), "journal"), c, testBoot())
	beginTest(t, j, c)
	if _, err := j.Finish(c, "unconfirmed", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*netbirdcommand.ControlRequest){
		func(r *netbirdcommand.ControlRequest) { r.SiteID++ },
		func(r *netbirdcommand.ControlRequest) {
			r.IssuedAt = r.IssuedAt.Add(-time.Minute)
			r.ExpiresAt = r.ExpiresAt.Add(-time.Minute)
		},
		func(r *netbirdcommand.ControlRequest) {
			r.IssuedAt = r.IssuedAt.Add(time.Minute)
			r.ExpiresAt = r.ExpiresAt.Add(time.Minute)
		},
	} {
		r := controlRequest(c, "release")
		mutate(&r)
		data, err := netbirdcommand.EncodeControl(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = j.Control(context.Background(), data); err == nil {
			t.Fatal("invalid authority released command")
		}
	}
	r := controlRequest(c, "release")
	data, _ := netbirdcommand.EncodeControl(r)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := j.Control(ctx, data); err == nil {
		t.Fatal("cancelled service released command")
	}
	if _, released, err := j.Query(c.RequestID, mustDigest(c)); err != nil || released != "" {
		t.Fatal("rejected request changed journal")
	}
	if _, _, err := j.Query(c.RequestID, strings.Repeat("f", 64)); !errors.Is(err, ErrConflict) {
		t.Fatal("incorrect digest read evidence")
	}
	j.Close()
	if s := j.State(time.Now()); s != (netbirdcommand.State{Status: "unavailable"}) {
		t.Fatal("closed owner ready")
	}
	if r := runControl(t, j, controlRequest(c, "state")); r.Outcome != "unavailable" {
		t.Fatal("closed owner returned live state")
	}
}
