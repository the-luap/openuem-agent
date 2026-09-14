package netbirdinstall

import (
	"context"
	"errors"
	"sync"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

var ErrRemoval = errors.New("the NetBird native removal could not be confirmed")

// Removal is an acquired native owner. Its caller must durably admit the exact
// command before Run, then retain this owner until Run and Close have joined.
type Removal struct {
	mu          sync.Mutex
	run         func(context.Context) error
	close       func() error
	ran, closed bool
	closeErr    error
}

func (*Removal) String() string               { return "[private native NetBird removal]" }
func (r *Removal) GoString() string           { return r.String() }
func (*Removal) MarshalJSON() ([]byte, error) { return nil, ErrRemoval }

func RemovalSupported() bool { return InstallationSupported() && nativeRemovalExecutionAvailable() }

// InspectRemoval returns either a complete installed-state descriptor or a
// positively verified absence. Missing or partial receipts alone are an error.
func InspectRemoval(ctx context.Context) (packageapi.Removal, bool, error) {
	if ctx == nil || ctx.Err() != nil || !RemovalSupported() {
		return packageapi.Removal{}, false, ErrRemoval
	}
	return nativeInspectRemoval(ctx)
}

func PrepareRemoval(ctx context.Context, requestID string, descriptor packageapi.Removal) (*Removal, error) {
	if ctx == nil || ctx.Err() != nil || !netbirdcommand.ValidRequestID(requestID) || !descriptor.Valid() || !RemovalSupported() {
		return nil, ErrRemoval
	}
	return prepareNativeRemoval(ctx, requestID, descriptor)
}

func (r *Removal) Run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrRemoval
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ran || r.closed || r.run == nil || ctx.Err() != nil {
		return ErrRemoval
	}
	r.ran = true
	if r.run(ctx) != nil || ctx.Err() != nil {
		return ErrRemoval
	}
	return nil
}

func (r *Removal) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		if r.close != nil && r.close() != nil {
			r.closeErr = ErrRemoval
		}
	}
	return r.closeErr
}
