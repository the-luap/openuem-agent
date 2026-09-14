package linuxservice

import (
	"context"
	"errors"
	"path"
	"sync"
)

var ErrRegistration = errors.New("persistent Linux service registration could not be verified")

type Status uint8

const (
	NotRegistered Status = iota
	Prepared
	Enabled
)

// Service owns the admitted unit, persistent enablement and private manager
// connection. Callers retain the admitted executable and enrollment identity.
// Close never unregisters, disables or stops the service.
type Service struct {
	mu         sync.Mutex
	closeOnce  sync.Once
	closed     bool
	spec       Spec
	unit       *unitFile
	enablement *unitEnablement
	connection *systemdConnection
}

func Open(ctx context.Context, spec Spec) (*Service, error) {
	return openServiceAt(ctx, spec, UnitPath, connectSystemd)
}

// Alternate paths and manager peers are private to owned native fixtures. The
// public entry point fixes both the installed unit path and the PID-1 manager.
func openServiceAt(ctx context.Context, spec Spec, filename string, connect func(context.Context) (*systemdConnection, error)) (_ *Service, resultErr error) {
	if ctx == nil || !spec.Valid() {
		return nil, ErrUnit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := &Service{spec: spec}
	defer func() {
		if resultErr != nil {
			s.Close()
		}
	}()
	var err error
	if s.unit, err = openUnitFileAt(filename, spec); err != nil {
		return nil, err
	}
	if s.enablement, err = openUnitEnablementAt(path.Dir(filename)); err != nil {
		return nil, err
	}
	if s.connection, err = connect(ctx); err != nil {
		return nil, err
	}
	if _, err := s.Status(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

type serviceObservation struct {
	definition unitDefinition
	file, link bool
}

func (o serviceObservation) status() Status {
	if !o.file {
		return NotRegistered
	}
	if o.definition.Present && o.definition.State.Enabled && o.link {
		return Enabled
	}
	return Prepared
}

// observe resolves even unloaded vendor definitions, then rechecks the retained
// files. A canonical file/link awaiting Reload is prepared, never enabled. A
// loaded foreign definition or enabled state without the canonical link fails.
func (s *Service) observe(ctx context.Context) (serviceObservation, error) {
	if s.closed {
		return serviceObservation{}, ErrUnit
	}
	if err := ctx.Err(); err != nil {
		return serviceObservation{}, err
	}
	file, err := s.unit.inspect()
	if err != nil {
		return serviceObservation{}, err
	}
	link, err := s.enablement.inspect()
	if err != nil {
		return serviceObservation{}, err
	}
	definition, err := s.connection.loadDefinition(ctx, s.spec)
	if err != nil {
		return serviceObservation{}, err
	}
	if after, err := s.unit.inspect(); err != nil || after != file {
		return serviceObservation{}, ErrUnit
	}
	if after, err := s.enablement.inspect(); err != nil || after != link {
		return serviceObservation{}, ErrUnit
	}
	if (!file && (definition.Present || link)) || (definition.State.Enabled && !link) {
		return serviceObservation{}, ErrUnit
	}
	return serviceObservation{definition: definition, file: file, link: link}, nil
}

// Status may load metadata but never publishes files, reloads, enables or starts
// a unit. Enabled means persistent registration is present, not agent readiness.
func (s *Service) Status(ctx context.Context) (Status, error) {
	if s == nil || ctx == nil {
		return NotRegistered, ErrUnit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	observation, err := s.observe(ctx)
	if err != nil {
		return NotRegistered, err
	}
	return observation.status(), nil
}

func (s *Service) reload(ctx context.Context) error {
	body, err := s.connection.call(ctx, managerPath, managerInterface+".Reload")
	if err != nil {
		return err
	}
	if len(body) != 0 {
		return ErrRegistration
	}
	return nil
}

// Register only enables the canonical unit, persistently and without force. All
// files survive an uncertain outcome, so another admitted invocation can resume.
// It never starts, restarts, stops, replaces, unmasks or resets a service.
func (s *Service) Register(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrUnit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.observe(ctx)
	if err != nil {
		return err
	}
	if !before.file {
		if err := s.unit.publish(ctx); err != nil {
			return err
		}
	}
	if err := s.unit.flush(ctx); err != nil {
		return err
	}
	if before.status() != Enabled {
		if err := s.reload(ctx); err != nil {
			return err
		}
		current, err := s.observe(ctx)
		if err != nil {
			return err
		}
		if !current.file || !current.definition.Present {
			return ErrRegistration
		}
		if current.status() != Enabled {
			// A protected link that remains unrecognized after Reload is a
			// conflict, not permission to repair or replace manager state.
			if current.link {
				return ErrRegistration
			}
			body, err := s.connection.call(ctx, managerPath, managerInterface+".EnableUnitFiles", []string{UnitName}, false, false)
			if err != nil {
				return err
			}
			if !validEnableReply(body) {
				return ErrRegistration
			}
			if err := s.enablement.flush(ctx); err != nil {
				return err
			}
			if err := s.reload(ctx); err != nil {
				return err
			}
		}
	}
	if err := s.enablement.flush(ctx); err != nil {
		return err
	}
	after, err := s.observe(ctx)
	if err != nil {
		return err
	}
	if after.status() != Enabled {
		return ErrRegistration
	}
	return ctx.Err()
}

func validEnableReply(body []any) bool {
	if len(body) != 2 || body[0] != true {
		return false
	}
	// The native codec decodes an array of structs to [][]any. Check every
	// member directly, without permissive Store conversions. Empty changes
	// allow an exact concurrent winner; the actual link must still verify.
	changes, ok := body[1].([][]any)
	if !ok || len(changes) > 1 {
		return false
	}
	for _, change := range changes {
		if len(change) != 3 || change[0] != "symlink" || change[1] != "/etc/systemd/system/"+wantsDirectory+"/"+UnitName || change[2] != UnitPath {
			return false
		}
	}
	return true
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		// Interrupt the manager first: an operation may hold mu while waiting
		// for a reply. Only then join it and release its file descriptors.
		s.connection.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closed = true
		s.enablement.Close()
		s.unit.Close()
	})
	return nil
}
