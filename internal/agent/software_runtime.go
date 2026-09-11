package agent

import (
	"context"
	"log"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/windowssoftware"
)

func (a *Agent) setSoftwareCapability(version int) {
	r := a.individual
	if r == nil {
		return
	}
	accepted := int32(0)
	if version == enrollment.SoftwareVersion && r.software != nil && r.identity != nil && r.identity.Platform == "windows" {
		accepted = int32(version)
	}
	r.softwareVersion.Store(accepted)
	if accepted == 0 {
		return
	}
	a.startSoftwareConsumer(func(ctx context.Context, plan enrollment.SoftwarePlan) enrollment.SoftwareOutcome {
		return windowssoftware.Execute(ctx, plan, r.directory, func() error {
			if r.softwareVersion.Load() != enrollment.SoftwareVersion {
				return enrollment.ErrSoftware
			}
			return r.software.live()
		})
	})
}

func (a *Agent) startSoftwareConsumer(execute softwareExecutor) {
	r := a.individual
	if r == nil || r.software == nil || execute == nil {
		return
	}
	r.mu.Lock()
	if r.stopping || r.softwareStarted {
		r.mu.Unlock()
		return
	}
	r.softwareStarted = true
	r.work.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.work.Done()
		defer func() {
			// Store, signing identity and service lease outlive this joined loop.
			// A retained receipt is persisted even after transport cancellation.
			if r.software.persistPending() != nil {
				log.Print("[ERROR]: protected Windows software receipt could not be persisted")
			}
		}()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		exchange := func(ctx context.Context, data []byte) ([]byte, error) {
			r.mu.Lock()
			connection := r.connection
			r.mu.Unlock()
			if connection == nil || connection.IsClosed() {
				return nil, enrollment.ErrSoftware
			}
			subject, err := enrollment.RequestSubject(r.identity.Response.DeviceID, "software")
			if err != nil {
				return nil, enrollment.ErrSoftware
			}
			message, err := connection.RequestWithContext(ctx, subject, data)
			if err != nil || message == nil {
				return nil, enrollment.ErrSoftware
			}
			return message.Data, nil
		}
		for {
			if r.softwareVersion.Load() == enrollment.SoftwareVersion {
				if r.software.cycle(r.ctx, exchange, execute) != nil && r.ctx.Err() == nil {
					log.Print("[ERROR]: private Windows software request failed")
				}
			} else if r.software.persistPending() != nil && r.ctx.Err() == nil {
				log.Print("[ERROR]: protected Windows software receipt could not be persisted")
			}
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
