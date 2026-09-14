package linuxservice

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/openuem-agent/internal/localready"
)

var ErrStart = errors.New("the registered Linux agent did not prove stable local readiness")

// Start requests at most one non-replacing start of the admitted, enabled unit.
// Readiness must be signed by the enrolled key and served by the manager's main
// process within one unchanged invocation. Close cancels and joins the wait but
// never stops a service whose start may already have succeeded.
func (s *Service) Start(ctx context.Context, identity localready.Identity, publicKey string) error {
	return s.start(ctx, identity, publicKey, localready.ProbeProcess)
}

func (s *Service) start(ctx context.Context, identity localready.Identity, publicKey string,
	probe func(context.Context, string, localready.Identity, string, uint32) error) error {
	if s == nil || s.lifetime == nil || ctx == nil || !identity.Valid() || !nkeys.IsValidPublicUserKey(publicKey) {
		return ErrStart
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	stop := context.AfterFunc(s.lifetime, cancel)
	defer stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.observe(ctx)
	if err != nil {
		return err
	}
	if before.status() != Enabled {
		return ErrRegistration
	}
	state := before.definition.State
	job := state.JobID
	if state.Active == "inactive" || state.Active == "failed" {
		if job != 0 {
			return ErrStart
		}
		body, err := s.connection.call(ctx, managerPath, managerInterface+".StartUnit", UnitName, "fail")
		if err != nil {
			return err
		}
		if job, err = startJob(body); err != nil {
			return err
		}
	} else if state.Active != "active" && state.Active != "activating" {
		return ErrStart
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var invocation unitState
	for {
		current, err := s.observe(ctx)
		if err != nil {
			if invocation.PID != 0 || !errors.Is(err, errUnitTransition) {
				return err
			}
			// Before binding a running process, a valid startup transition may
			// straddle the metadata reads. Reobserve everything after waiting;
			// malformed/foreign properties and changes during a probe fail.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				continue
			}
		}
		state = current.definition.State
		if current.status() != Enabled || (state.JobID != 0 && state.JobID != job) || !identity.Valid() {
			return ErrStart
		}
		if invocation.PID != 0 && !sameInvocation(invocation, state) {
			return ErrStart
		}
		switch state.Active {
		case "active":
			if state.JobID == 0 {
				invocation = state
				probeErr := probe(ctx, s.spec.IdentityDirectory, identity, publicKey, state.PID)
				// Even a negative response is fenced before another retry. Do not
				// silently follow an automatic restart into a new invocation.
				after, err := s.observe(ctx)
				if err != nil {
					return err
				}
				if after.status() != Enabled || after.definition.State != state {
					return ErrStart
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				if probeErr == nil {
					return nil
				}
				if errors.Is(probeErr, localready.ErrConflict) {
					return probeErr
				}
			}
		case "activating":
			if state.Substate == "auto-restart" {
				return ErrStart
			}
		case "inactive":
			if state.JobID == 0 {
				return ErrStart
			}
		default:
			return ErrStart
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func sameInvocation(a, b unitState) bool {
	return a.PID == b.PID && a.StartedMonotonic == b.StartedMonotonic && a.ExecStartedMonotonic == b.ExecStartedMonotonic && a.Invocation == b.Invocation
}

func startJob(body []any) (uint32, error) {
	if len(body) != 1 {
		return 0, ErrStart
	}
	object, ok := body[0].(dbus.ObjectPath)
	if !ok {
		return 0, ErrStart
	}
	const prefix = "/org/freedesktop/systemd1/job/"
	value, ok := strings.CutPrefix(string(object), prefix)
	if !ok || len(value) > 10 {
		return 0, ErrStart
	}
	id, err := strconv.ParseUint(value, 10, 32)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != value {
		return 0, ErrStart
	}
	return uint32(id), nil
}
