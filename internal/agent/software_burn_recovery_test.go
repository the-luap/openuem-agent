package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/windowssoftware"
)

// This fixture supplies an already admitted historical Burn task. It must not
// enable new Burn admission, require another download, or rerun installation.
func historicalBurnTask(t *testing.T, f *softwareRuntimeFixture, operation string) {
	t.Helper()
	secret, err := f.client.key.Open(*f.task, f.client.authority, f.client.scope, f.recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	plan := secret.Plan
	plan.Kind, plan.Operation, plan.MSIProperties = "windows-burn", operation, nil
	plan.Artifact.Format, plan.Artifact.URL = "exe", "https://uncontacted.example.test/bundle.exe"
	plan.Arguments = []string{"/quiet", "/norestart"}
	if operation == "remove" {
		plan.Arguments = append([]string{"/uninstall"}, plan.Arguments...)
	}
	plan.Detection = enrollment.SoftwareDetection{Kind: "uninstall-key", UninstallKey: plan.Detection.ProductCode, RegistryView: "64", Version: plan.Version}
	c := f.task.Context
	c.PlanHash, err = plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	c.Expectation = plan.Expectation()
	capable := f.recipient
	capable.BurnVersion = enrollment.SoftwareBurnVersion
	nonce := secret.Nonce()
	defer clear(nonce)
	f.task, err = enrollment.SealSoftwareTask(capable, c, plan, nonce, f.client.authority, f.issuer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if f.journal.entry == nil {
		boot, err := f.client.bootSession()
		if err != nil {
			t.Fatal(err)
		}
		f.journal.entry = &enrollmentstore.SoftwareEntry{Nonce: bytes.Clone(nonce), BootSession: boot}
	}
	f.journal.entry.Task = *f.task
}

func TestSoftwareBurnHistoryRecoversWithoutNewAdmission(t *testing.T) {
	for _, state := range []string{"uncertain", "restart_required"} {
		t.Run(state, func(t *testing.T) {
			f := newSoftwareRuntimeFixture(t)
			historicalBurnTask(t, f, "install")
			var original []byte
			if state == "restart_required" {
				code := uint32(3010)
				out := enrollment.SoftwareOutcome{State: state, Execution: "started", ExitCode: &code, Before: enrollment.SoftwareObservation{State: "absent"}, After: enrollment.SoftwareObservation{State: "unknown"}}
				if err := f.client.produce(*f.task, f.journal.entry.Nonce, out); err != nil {
					t.Fatal(err)
				}
				original, _ = json.Marshal(f.journal.entry.Result)
				defer clear(original)
				f.client.clearPending()
			}
			f.client.bootSession = func() (windowssoftware.BootSession, error) {
				t.Error("historical receipt attempted new native admission")
				return windowssoftware.BootSession{}, windowssoftware.ErrBootEvidence
			}
			f.loseReply = true
			exchange := f.exchange(t)
			execute := func(context.Context, enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
				t.Error("historical Burn task reached executable work")
				return softwareInterrupted()
			}
			if err := f.client.cycle(t.Context(), exchange, execute); err == nil || f.client.pending == nil || !f.client.persisted {
				t.Fatal("lost historical Burn receipt discarded durable evidence")
			}
			if err := f.client.cycle(t.Context(), exchange, execute); err != nil || f.client.pending != nil {
				t.Fatal("historical Burn receipt did not recover", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.result == nil || f.result.Outcome.State != state || f.polls != 1 || f.reports != 2 {
				t.Fatal("historical Burn result was changed or repolled")
			}
			if len(original) != 0 {
				got, _ := json.Marshal(f.result)
				defer clear(got)
				if !bytes.Equal(got, original) {
					t.Fatal("signed pre-restart Burn evidence was rewritten")
				}
			}
		})
	}
}

func TestSoftwareBurnPostBootReconciliationKeepsExactReadOnlyRule(t *testing.T) {
	for _, tc := range []struct{ operation, observation, want string }{
		{"install", "present", "observed"}, {"install", "absent", "drifted"},
		{"remove", "absent", "observed"}, {"remove", "present", "drifted"},
		{"install", "unknown", "unknown"}, {"install", "same-boot", "waiting_for_boot"},
	} {
		t.Run(tc.operation+"/"+tc.observation, func(t *testing.T) {
			f := newSoftwareReconciliationRuntimeFixture(t)
			historicalBurnTask(t, f.softwareRuntimeFixture, tc.operation)
			f.signReconciliation(t, time.Now(), time.Now().Add(5*time.Minute))
			reads := 1
			if tc.observation == "same-boot" {
				reads = 0
				f.client.bootSession = func() (windowssoftware.BootSession, error) { return f.journal.entry.BootSession, nil }
			}
			observer := func(ctx context.Context, rule windowssoftware.Rule) (windowssoftware.Observation, error) {
				// Reuse the fixture's exact signed rule and bounded-context checks.
				value, err := f.observe(t)(ctx, rule)
				if rule.Kind != "uninstall-key" || rule.RegistryView != "64" {
					t.Error("Burn observation lost its explicit registration view")
				}
				if tc.observation != "present" {
					value = windowssoftware.Observation{State: tc.observation}
				}
				return value, err
			}
			if err := f.client.reconcile(t.Context(), f.exchange(t), observer); err != nil {
				t.Fatal(err)
			}
			if f.journal.saved == nil || !f.journal.saved.Acknowledged || f.journal.saved.Result.Outcome.State != tc.want || f.observations != reads || f.runs != 0 {
				t.Fatal("Burn reconciliation changed the signed expectation or boot requirement")
			}
		})
	}
}
