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
	// Installation acquires an exact prepared package before journal admission,
	// retaining its ownership through execution and joined cleanup.
	install func(context.Context, netbirdcommand.Command) (*installationLease, error)
	now     func() time.Time
}

type installationLease struct {
	revision string
	run      func(context.Context) error
	release  func() error
	closed   bool
	closeErr error
}

func (l *installationLease) close() error {
	if l != nil && !l.closed {
		l.closed = true
		if l.release != nil {
			l.closeErr = l.release()
		}
	}
	if l == nil {
		return nil
	}
	return l.closeErr
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
	ctx, cancel := context.WithDeadline(parent, c.ExpiresAt)
	defer cancel()
	if ctx.Err() != nil {
		return netbirdcommand.Receipt{}, ErrActionUnconfirmed
	}
	run := e.run
	var lease *installationLease
	if c.Version == netbirdcommand.InstallationVersion {
		if e.install == nil {
			return netbirdcommand.ReceiptFor(c, "rejected")
		}
		lease, err = e.install(ctx, c)
		if lease != nil {
			defer lease.close()
		}
		if err != nil || lease == nil || lease.run == nil || lease.release == nil || !netbirdcommand.ValidDigest(lease.revision) {
			return netbirdcommand.ReceiptFor(c, "rejected")
		}
		run = func(ctx context.Context, _ netbirdcommand.Command) error { return lease.run(ctx) }
	}
	if run == nil {
		return netbirdcommand.ReceiptFor(c, "rejected")
	}
	var admitted bool
	if lease != nil {
		admitted, receipt, err = e.journal.BeginPrepared(c, e.now(), lease.revision)
	} else {
		admitted, receipt, err = e.journal.Begin(c, e.now())
	}
	if err != nil {
		return netbirdcommand.Receipt{}, ErrActionUnconfirmed
	}
	if !admitted {
		if receipt == nil {
			return netbirdcommand.Receipt{}, ErrActionUnconfirmed
		}
		return *receipt, nil
	}
	status := "unconfirmed"
	if ctx.Err() == nil {
		if err = run(ctx, c); err == nil && ctx.Err() == nil {
			status = "completed"
		}
	}
	if lease != nil && lease.close() != nil {
		status = "unconfirmed"
	}
	receipt, err = e.journal.Finish(c, status, e.now())
	if err != nil || receipt == nil {
		return netbirdcommand.Receipt{}, ErrActionUnconfirmed
	}
	return *receipt, nil
}
