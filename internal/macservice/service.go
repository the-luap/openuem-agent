// Package macservice registers the admitted macOS app's bundled LaunchDaemon.
// Authorization status is distinct from the agent's authenticated readiness.
package macservice

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrUnsupported  = errors.New("app service registration requires macOS 13 or newer and native framework support")
	ErrAccess       = errors.New("the installed app bundle or its protected metadata is unavailable or changed")
	ErrSignature    = errors.New("the installed app requires a valid notarized Developer ID Application signature")
	ErrRegistration = errors.New("the bundled app service registration could not be verified")
)

type Status uint8

const (
	NotRegistered Status = iota
	Enabled
	RequiresApproval
	NotFound
)

type nativeService interface {
	status() (Status, error)
	register() error
	close() error
}

// Service owns read-only installation descriptors and a native SMAppService.
// Close releases these local resources; it never unregisters or stops a daemon.
type Service struct {
	mu         sync.Mutex
	native     nativeService
	check      func(context.Context, bool) error
	closeFiles func() error
}

func Open(ctx context.Context, executablePath string) (*Service, error) {
	if ctx == nil {
		return nil, ErrAccess
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return openNative(ctx, executablePath)
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	if s == nil || ctx == nil {
		return NotFound, ErrAccess
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native == nil {
		return NotFound, ErrAccess
	}
	if err := s.check(ctx, false); err != nil {
		return NotFound, err
	}
	status, err := s.native.status()
	if contextErr := ctx.Err(); contextErr != nil {
		return NotFound, contextErr
	}
	if err != nil || status > NotFound {
		return NotFound, ErrRegistration
	}
	return status, nil
}

// Register preserves an existing registration or a user's pending/revoked
// approval. It never unregisters, reconfigures a legacy job, or opens Settings.
// Native framework calls are synchronous; cancellation is checked around them.
func (s *Service) Register(ctx context.Context) (Status, error) {
	if s == nil || ctx == nil {
		return NotFound, ErrAccess
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native == nil {
		return NotFound, ErrAccess
	}
	if err := s.check(ctx, true); err != nil {
		return NotFound, err
	}
	status, err := s.native.status()
	if err != nil || status >= NotFound {
		return NotFound, ErrRegistration
	}
	if err := ctx.Err(); err != nil {
		return status, err
	}
	if status == NotRegistered {
		_ = s.native.register()
		// The native API can return AlreadyRegistered or LaunchDeniedByUser.
		// Use its subsequent authorization state, never an error's human text.
		status, err = s.native.status()
		if err != nil || (status != Enabled && status != RequiresApproval) {
			return NotRegistered, ErrRegistration
		}
	}
	if err := s.check(ctx, false); err != nil {
		return status, err
	}
	return status, nil
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.native != nil {
		err = s.native.close()
		s.native = nil
	}
	if s.closeFiles != nil {
		if closeErr := s.closeFiles(); err == nil {
			err = closeErr
		}
		s.closeFiles = nil
	}
	return err
}
