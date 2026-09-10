// Package lifecycle serializes service initialization and cleanup. Readiness
// means local initialization succeeded; it does not assert server connectivity.
package lifecycle

import (
	"context"
	"errors"
)

type Runtime interface {
	Start() error
	Stop()
}

// Readiness separates an initialized, stoppable controller from a usable Agent.
// A recovering controller owns its cleanup and may accept service controls while
// withholding agent readiness until a protected identity can start safely.
type Readiness interface {
	Ready() <-chan struct{}
}

type Factory func(context.Context) (Runtime, error)

type Phase uint8

const (
	Initializing Phase = iota
	Ready
	Stopping
	Recovering
)

// Run never calls Stop concurrently with the factory or Start. A stop received
// during initialization cancels their context and waits for ownership to return.
// A factory must return nil on failure or transfer any partial runtime for cleanup.
// notify is synchronous, ordered, and must not call back into the runtime.
func Run(ctx context.Context, factory Factory, notify func(Phase)) error {
	if ctx == nil || factory == nil || notify == nil {
		return errors.New("service lifecycle configuration is invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	notify(Initializing)
	var runtime Runtime
	defer func() {
		notify(Stopping)
		if runtime != nil {
			runtime.Stop()
		}
	}()
	var err error
	runtime, err = factory(ctx)
	if err != nil {
		return err
	}
	if runtime == nil {
		return errors.New("service runtime is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := runtime.Start(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if readiness, ok := runtime.(Readiness); ok {
		ready := readiness.Ready()
		if ready == nil {
			return errors.New("service readiness signal is unavailable")
		}
		select {
		case <-ready:
		default:
			notify(Recovering)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ready:
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	notify(Ready)
	<-ctx.Done()
	return ctx.Err()
}
