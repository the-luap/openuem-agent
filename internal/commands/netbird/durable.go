package netbird

import (
	"context"
	"sync"
	"time"

	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
)

// DurableExecutor joins a validated command sequence with its permanent local
// attempt/result. Its owner must retain the journal and current service identity
// until all Execute calls have returned. This is not a legacy-message adapter.
type DurableExecutor struct {
	mu      sync.Mutex
	journal *netbirdjournal.Journal
	run     func(context.Context, netbirdcommand.Command) error
	// Installation must acquire its own native runner and prepared package.
	// A nil runner rejects new installation attempts before journal admission.
	install func(context.Context, netbirdcommand.Command) error
	now     func() time.Time
}

func NewDurableExecutor(journal *netbirdjournal.Journal) (*DurableExecutor, error) {
	if journal == nil {
		return nil, ErrInvalidAction
	}
	return &DurableExecutor{journal: journal, now: time.Now, run: func(ctx context.Context, c netbirdcommand.Command) error {
		result, err := performActionContext(ctx, c.Operation, nats.NetbirdSettings{ManagementURL: c.ManagementURL, Profile: c.Profile, OneOffKey: c.SetupKey})
		if err != nil || result == nil {
			return ErrActionUnconfirmed
		}
		return nil
	}}, nil
}

// Execute never retries an attempt. Reading an existing matching receipt after
// command expiry is allowed; starting a new expired command is forbidden.
func (e *DurableExecutor) Execute(parent context.Context, data []byte) (netbirdcommand.Receipt, error) {
	c, err := netbirdcommand.Decode(data)
	if err != nil {
		return netbirdcommand.Receipt{}, ErrInvalidAction
	}
	if parent == nil || parent.Err() != nil {
		return netbirdcommand.Receipt{}, ErrActionUnconfirmed
	}
	if !e.mu.TryLock() {
		return netbirdcommand.ReceiptFor(c, "busy")
	}
	defer e.mu.Unlock()
	receipt, err := e.journal.Lookup(c)
	if err != nil {
		return netbirdcommand.Receipt{}, ErrActionUnconfirmed
	}
	if receipt != nil {
		return *receipt, nil
	}
	if parent.Err() != nil {
		return netbirdcommand.Receipt{}, ErrActionUnconfirmed
	}
	run := e.run
	if c.Version == netbirdcommand.InstallationVersion {
		run = e.install
	}
	if run == nil {
		return netbirdcommand.ReceiptFor(c, "rejected")
	}
	admitted, receipt, err := e.journal.Begin(c, e.now())
	if err != nil {
		return netbirdcommand.Receipt{}, ErrActionUnconfirmed
	}
	if !admitted {
		if receipt == nil {
			return netbirdcommand.Receipt{}, ErrActionUnconfirmed
		}
		return *receipt, nil
	}
	ctx, cancel := context.WithDeadline(parent, c.ExpiresAt)
	defer cancel()
	status := "unconfirmed"
	if ctx.Err() == nil {
		if err = run(ctx, c); err == nil && ctx.Err() == nil {
			status = "completed"
		}
	}
	receipt, err = e.journal.Finish(c, status, e.now())
	if err != nil || receipt == nil {
		return netbirdcommand.Receipt{}, ErrActionUnconfirmed
	}
	return *receipt, nil
}
