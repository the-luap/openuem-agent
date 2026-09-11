package agent

import (
	"context"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
)

func TestSoftwareServiceRequiresExactCapabilityAndProtectedClient(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	r := f.agent.individual
	r.software = f.client
	r.cancel()
	for _, version := range []int{0, 2, -1, enrollment.SoftwareVersion, 0} {
		f.agent.setSoftwareCapability(version)
		r.work.Wait()
		want := int32(0)
		if version == enrollment.SoftwareVersion {
			want = int32(version)
		}
		if r.softwareVersion.Load() != want {
			t.Fatal("incompatible software capability enabled", version)
		}
	}
	r.identity.Platform = "macos"
	f.agent.setSoftwareCapability(enrollment.SoftwareVersion)
	if r.softwareVersion.Load() != 0 {
		t.Fatal("Mac enabled Windows software")
	}
	r.identity.Platform = "windows"
	r.software = nil
	f.agent.setSoftwareCapability(enrollment.SoftwareVersion)
	if r.softwareVersion.Load() != 0 || f.journal.entry != nil || f.runs != 0 {
		t.Fatal("missing protected client admitted software")
	}
	(&Agent{}).setSoftwareCapability(enrollment.SoftwareVersion)
}

func TestSoftwareServiceShutdownJoinsExecutionAndPersistsBeforeKeyRelease(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	r := f.agent.individual
	r.software = f.client
	r.softwareVersion.Store(enrollment.SoftwareVersion)
	_ = f.exchange(t)
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		r.cancel()
		select {
		case <-release:
		default:
			close(release)
		}
		r.work.Wait()
	})
	f.agent.startSoftwareConsumer(func(ctx context.Context, plan enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
		if f.journal.entry == nil || f.journal.entry.Result != nil || plan.MSIProperties["LICENSEKEY"] != "private-license" {
			t.Error("service skipped exclusive durable admission")
		}
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
		if !enrollment.ValidRecoveryPublicKey(f.client.key.PublicKey()) || f.client.identity.Keys.Certificate == nil {
			t.Error("service released keys during native work")
		}
		return softwareInterrupted()
	})
	f.agent.startSoftwareConsumer(func(context.Context, enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
		t.Error("second software consumer started")
		return softwareInterrupted()
	})
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("joined software service did not consume the authenticated WSS task")
	}
	done := make(chan struct{})
	go func() { f.agent.Stop(); close(done) }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("service did not cancel active software work")
	}
	select {
	case <-done:
		t.Fatal("service stop returned while native work remained")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("service did not join software result persistence")
	}
	if f.journal.entry == nil || f.journal.entry.Result == nil || f.journal.entry.Result.Outcome.State != "uncertain" {
		t.Fatal("shutdown lost durable interrupted outcome")
	}
	if enrollment.VerifySoftwareResult(*f.journal.entry.Result, f.client.certificate, time.Now()) != nil {
		t.Fatal("shutdown receipt was not signed before key release")
	}
}

func TestSoftwareServiceUsesItsIndividualConnectionAndPreservesReceipt(t *testing.T) {
	f := newSoftwareRuntimeFixture(t)
	r := f.agent.individual
	r.software = f.client
	r.softwareVersion.Store(enrollment.SoftwareVersion)
	f.loseReply = true
	_ = f.exchange(t)
	t.Cleanup(func() { r.cancel(); r.work.Wait() })
	f.agent.startSoftwareConsumer(f.execute(t))
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		f.mu.Lock()
		received := f.result != nil
		f.mu.Unlock()
		if received {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("software service did not submit over private WSS")
		case <-ticker.C:
		}
	}
	r.cancel()
	r.work.Wait()
	if f.runs != 1 || f.client.pending == nil || !f.client.persisted || f.journal.entry.Result == nil {
		t.Fatal("service lost receipt after reply failure")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reports != 1 || f.polls != 1 {
		t.Fatal("service repeated an admitted native attempt", f.reports, f.polls)
	}
}
