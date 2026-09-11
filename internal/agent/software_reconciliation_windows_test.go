package agent

import (
	"os"
	"testing"

	"github.com/open-uem/openuem-agent/internal/windowssoftware"
)

// Exercise the same early read-only helper dispatch as the installed service.
func TestMain(m *testing.M) {
	if handled, code := windowssoftware.HandleHelper(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func TestNativeWindowsSoftwareReconciliationReadOnlyHelper(t *testing.T) {
	f := newSoftwareReconciliationRuntimeFixture(t)
	// The nonce, command, prior admission and later-boot comparison are owned
	// synthetic evidence. Only the exact machine MSI query runs natively here;
	// this fixture does not claim to reboot or install a product on the runner.
	if err := f.client.reconcile(t.Context(), f.exchange(t), windowssoftware.Observe); err != nil {
		t.Fatal("native read-only helper did not return a durable receipt", err)
	}
	if f.journal.saved == nil || !f.journal.saved.Acknowledged || f.journal.saved.Result.Outcome.State != "drifted" || f.journal.saved.Result.Outcome.Observation.State != "absent" || f.runs != 0 {
		t.Fatal("native helper did not observe the uninstalled fixture product")
	}
}
