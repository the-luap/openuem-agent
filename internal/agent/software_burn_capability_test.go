package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/windowssoftware"
)

func burnRegistrationReply(t *testing.T, f *softwareRuntimeFixture, request *enrollment.SoftwareRequest, version int, id string) enrollment.SoftwareReply {
	t.Helper()
	reply := enrollment.SoftwareReply{Version: 1, Protocol: enrollment.SoftwareProtocol, OK: true}
	switch request.Action {
	case "challenge":
		if request.BurnVersion != version {
			t.Fatal("challenge did not request the current profile version")
		}
		reply.Registration = &enrollment.SoftwareRegistration{Version: 1, Protocol: enrollment.SoftwareProtocol, Identity: f.client.scope, ID: id, PublicKey: f.recipient.PublicKey, Nonce: bytes.Repeat([]byte{2}, 32), ExpiresAt: time.Now().Add(time.Minute).Unix(), BurnVersion: version}
	case "register":
		if request.BurnVersion != 0 || request.Registration == nil || request.Registration.BurnVersion != version || request.Registration.ID != id || enrollment.VerifySoftwareRegistration(*request.Registration, request.Signature, f.client.certificate, time.Now()) != nil {
			t.Fatal("recipient capability was not bound to its device signature")
		}
		reply.Recipient = &enrollment.SoftwareRecipient{ID: id, Identity: f.client.scope, PublicKey: f.recipient.PublicKey, BurnVersion: version}
	default:
		t.Fatal("unexpected registration action", request.Action)
	}
	return reply
}

func TestSoftwareBurnRegistrationTracksProfileAndSignsEachChange(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	previousID := ""
	for _, version := range []int{0, 1, 0, 1} {
		f.client.burnVersion.Store(int32(version))
		id := uuid.NewString()
		var actions []string
		exchange := func(_ context.Context, data []byte) ([]byte, error) {
			request, err := enrollment.DecodeSoftwareRequest(data, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			actions = append(actions, request.Action)
			if request.Action == "poll" {
				if request.RecipientID != id || request.RecipientID == previousID || f.client.recipientBurnVersion != version {
					t.Fatal("poll used an obsolete or unsigned recipient")
				}
				return json.Marshal(enrollment.SoftwareReply{Version: 1, Protocol: enrollment.SoftwareProtocol, OK: true})
			}
			return json.Marshal(burnRegistrationReply(t, f, request, version, id))
		}
		if err := f.client.cycle(t.Context(), exchange, func(context.Context, enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
			t.Fatal("empty poll executed work")
			return softwareInterrupted()
		}); err != nil || !reflect.DeepEqual(actions, []string{"challenge", "register", "poll"}) || f.client.recipientBurnVersion != version {
			t.Fatal("profile change did not renegotiate before polling", actions, err)
		}
		previousID = id
	}
}

func TestSoftwareBurnRegistrationRejectsChangedOrMismatchedGrant(t *testing.T) {
	for _, stage := range []string{"challenge-version", "cached-recipient-version", "registered-version", "withdraw-at-challenge", "withdraw-at-register"} {
		t.Run(stage, func(t *testing.T) {
			f := newSoftwareRuntimeFixture(t)
			f.client.burnVersion.Store(1)
			calls := 0
			exchange := func(_ context.Context, data []byte) ([]byte, error) {
				calls++
				request, err := enrollment.DecodeSoftwareRequest(data, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				reply := burnRegistrationReply(t, f, request, 1, f.recipient.ID)
				if request.Action == "challenge" {
					switch stage {
					case "challenge-version":
						reply.Registration.BurnVersion = 0
					case "cached-recipient-version":
						reply.Registration, reply.Recipient = nil, &f.recipient
					case "withdraw-at-challenge":
						f.client.burnVersion.Store(0)
					}
				} else if stage == "registered-version" {
					reply.Recipient.BurnVersion = 0
				} else if stage == "withdraw-at-register" {
					f.client.burnVersion.Store(0)
				}
				return json.Marshal(reply)
			}
			wantCalls := 1
			if stage == "registered-version" || stage == "withdraw-at-register" {
				wantCalls = 2
			}
			if err := f.client.register(t.Context(), exchange); err == nil || calls != wantCalls || f.client.recipientID != "" || f.client.recipientBurnVersion != 0 {
				t.Fatal("changed profile or mismatched capability acquired a recipient", calls, err)
			}
		})
	}
}

func TestSoftwareBurnNewAdmissionAndWithdrawalKeepDurableTruth(t *testing.T) {
	for _, stage := range []string{"enabled", "withdraw-before-boot", "withdraw-during-boot", "withdraw-after-admission"} {
		t.Run(stage, func(t *testing.T) {
			f := newSoftwareRuntimeFixture(t)
			historicalBurnTask(t, f, "install")
			f.journal.entry.Close()
			f.journal.entry = nil // This task has never been admitted.
			f.recipient.BurnVersion = 1
			f.client.burnVersion.Store(1)
			boot := f.client.bootSession
			boots, runs := 0, 0
			f.client.bootSession = func() (windowssoftware.BootSession, error) {
				boots++
				if stage == "withdraw-during-boot" && boots == 1 || stage == "withdraw-after-admission" && boots == 2 {
					f.client.burnVersion.Store(0)
				}
				return boot()
			}
			transport := f.exchange(t)
			exchange := func(ctx context.Context, data []byte) ([]byte, error) {
				request, err := enrollment.DecodeSoftwareRequest(data, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				reply, err := transport(ctx, data)
				if request.Action == "poll" && stage == "withdraw-before-boot" {
					f.client.burnVersion.Store(0)
				}
				return reply, err
			}
			err := f.client.cycle(t.Context(), exchange, func(_ context.Context, plan enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
				runs++
				if plan.Kind != "windows-burn" || f.journal.entry == nil || f.client.recipientBurnVersion != 1 {
					t.Fatal("Burn execution skipped signed capability or durable admission")
				}
				code := uint32(0)
				return enrollment.SoftwareOutcome{State: "observed", Execution: "started", ExitCode: &code, Before: enrollment.SoftwareObservation{State: "absent"}, After: enrollment.SoftwareObservation{State: "present", Version: plan.Version}}
			})
			switch stage {
			case "enabled":
				if err != nil || runs != 1 || f.journal.entry == nil || f.journal.entry.Result.Outcome.State != "observed" {
					t.Fatal("negotiated Burn did not execute and persist its exact result", err)
				}
			case "withdraw-after-admission":
				if err != nil || runs != 0 || f.journal.entry == nil || f.journal.entry.Result.Outcome.State != "not_started" {
					t.Fatal("withdrawal after admission lost the not-started result", err)
				}
			default:
				if err == nil || runs != 0 || f.journal.entry != nil || stage == "withdraw-before-boot" && boots != 0 {
					t.Fatal("withdrawn Burn acquired a new durable attempt", err)
				}
			}
		})
	}
}

func TestSoftwareBurnReceiptPrecedesCapabilityDowngrade(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	historicalBurnTask(t, f, "install")
	f.client.recipientID, f.client.recipientBurnVersion = f.recipient.ID, 1
	if err := f.client.produce(*f.task, f.journal.entry.Nonce, softwareInterrupted()); err != nil {
		t.Fatal(err)
	}
	original, _ := json.Marshal(f.client.pending)
	defer clear(original)
	f.loseReply = true
	exchange := f.exchange(t)
	for attempt := range 2 {
		err := f.client.cycle(t.Context(), exchange, func(context.Context, enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
			t.Fatal("capability downgrade reran retained work")
			return softwareInterrupted()
		})
		if (err != nil) != (attempt == 0) {
			t.Fatal("lost receipt did not retry", err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	wire, _ := json.Marshal(f.result)
	defer clear(wire)
	if f.polls != 0 || f.reports != 2 || !bytes.Equal(original, wire) || f.client.recipientBurnVersion != 1 || f.client.pending != nil {
		t.Fatal("downgrade replaced a retained result before its receipt")
	}
}

func TestSoftwareBurnProfileRequiresProtectedNativeWindowsClient(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	r := f.agent.individual
	r.software = f.client
	r.cancel()
	for _, tc := range []struct {
		platform, architecture string
		software, burn, want   int
	}{
		{"windows", "amd64", 1, 1, 1}, {"windows", "arm64", 1, 1, 1},
		{"windows", "386", 1, 1, 0}, {"macos", "arm64", 1, 1, 0},
		{"windows", "amd64", 0, 1, 0}, {"windows", "amd64", 2, 1, 0},
		{"windows", "amd64", 1, 2, 0}, {"windows", "amd64", 1, -1, 0},
		{"windows", "amd64", 1, 0, 0},
	} {
		t.Run(fmt.Sprintf("%s-%s-%d-%d", tc.platform, tc.architecture, tc.software, tc.burn), func(t *testing.T) {
			r.identity.Platform, r.identity.Architecture = tc.platform, tc.architecture
			f.agent.setSoftwareCapabilities(tc.software, 0, tc.burn)
			r.work.Wait()
			if f.client.requestedBurnVersion() != tc.want {
				t.Fatal("Burn permission ignored protected platform or exact profile version")
			}
		})
	}
	f.agent.setSoftwareCapability(1)
	if f.client.requestedBurnVersion() != 0 {
		t.Fatal("legacy profile retained Burn permission")
	}
}
