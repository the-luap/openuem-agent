package agent

import (
	"context"
	"errors"
	"log"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/openuem-agent/internal/localready"
)

type readinessEndpoint interface {
	MarkReady() error
	Close() error
}

type readinessListener func(context.Context, string, localready.Identity, nkeys.KeyPair) (readinessEndpoint, error)

// startInitializedScheduler is called by native desktop runtimes only after all
// initialization and initial job registration succeeded. Readiness attests to
// local initialization, including an initialized offline reconnect schedule.
// Inventory delivery and broker connectivity remain separate server observations.
func (a *Agent) startInitializedScheduler(listen readinessListener) error {
	if a.ctx == nil || a.TaskScheduler == nil {
		return errors.New("agent has not been initialized")
	}
	if err := a.ctx.Err(); err != nil {
		return err
	}
	r := a.individual
	if r != nil && r.identity != nil && (r.identity.AgentSize > 0 || r.identity.AgentSHA256 != "") {
		if r.readiness != nil || r.identity.Keys == nil || listen == nil {
			return localready.ErrUnavailable
		}
		i := r.identity
		identity := localready.Identity{
			DeviceID: i.Response.DeviceID, TenantID: i.Response.TenantID, SiteID: i.Response.SiteID,
			ReleaseDigest: i.ReleaseDigest, AgentSize: i.AgentSize, AgentSHA256: i.AgentSHA256,
			ExpiresAt: i.Response.ExpiresAt,
		}
		endpoint, err := listen(a.ctx, r.directory, identity, i.Keys.Broker)
		// Own a partially returned endpoint as well, so service cleanup joins it
		// on failure. Start and Stop are serialized by the service lifecycle.
		r.readiness = endpoint
		if err != nil {
			return err
		}
		if endpoint == nil {
			return localready.ErrUnavailable
		}
	}
	if err := a.ctx.Err(); err != nil {
		return err
	}
	a.TaskScheduler.Start()
	if r != nil && r.readiness != nil {
		if err := r.readiness.MarkReady(); err != nil {
			return err
		}
	}
	if err := a.ctx.Err(); err != nil {
		return err
	}
	log.Println("[INFO]: agent scheduler has started")
	return nil
}
