package netbird

import (
	"context"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
)

// DurableService owns the journal and joins every admitted broker handler before
// closing it. The caller must supply a validated native identity and certificate
// expiry, and exclude legacy/profile mutations before publishing readiness.
type DurableService struct {
	mu            sync.Mutex
	closeOnce     sync.Once
	work          sync.WaitGroup
	closed        bool
	ctx           context.Context
	cancel        context.CancelFunc
	identity      netbirdcommand.Identity
	expires       time.Time
	journal       *netbirdjournal.Journal
	executor      *DurableExecutor
	preparation   *preparationOwner
	installation  installationPlanner
	connection    *nats.Conn
	binding       *netbirdServiceBinding
	subscriptions []*nats.Subscription
	closeErr      error
}

type netbirdServiceBinding struct{ connection *nats.Conn }

// NewDurableService transfers journal ownership on success. A failed creation
// leaves ownership with the caller. The service's identity is immutable until
// all handlers join and a subsequent service opens the retained journal.
func NewDurableService(parent context.Context, journal *netbirdjournal.Journal, identity netbirdcommand.Identity, expires time.Time) (*DurableService, error) {
	if parent == nil || parent.Err() != nil || !identity.Valid() || !expires.After(time.Now()) {
		return nil, ErrInvalidAction
	}
	executor, err := NewDurableExecutor(journal)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(parent, expires)
	return &DurableService{ctx: ctx, cancel: cancel, identity: identity, expires: expires, journal: journal, executor: executor}, nil
}

// Bind installs exact direct subscriptions on a current connection. Ordinary
// reconnects retain those subscriptions; replacing the connection removes the
// prior subscriptions. The journal/executor remain the same across connection changes.
func (s *DurableService) Bind(connection *nats.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil || connection == nil || connection.IsClosed() {
		return ErrActionUnconfirmed
	}
	if s.connection == connection {
		return nil
	}
	for _, sub := range s.subscriptions {
		_ = sub.Unsubscribe()
	}
	s.subscriptions = nil
	s.connection = nil
	binding := &netbirdServiceBinding{connection: connection}
	s.binding = binding
	command, _ := netbirdcommand.Subject(s.identity.DeviceID)
	control, _ := netbirdcommand.ControlSubject(s.identity.DeviceID)
	subjects := []string{command, control}
	prepare, err := netbirdcommand.PreparationSubject(s.identity.DeviceID)
	if s.identity.Individual && err == nil {
		subjects = append(subjects, prepare)
	}
	for _, subject := range subjects {
		kind := subject == control
		handler := s.handler(kind, subject, binding)
		if subject == prepare {
			handler = s.preparationHandler(subject, binding)
		}
		sub, err := connection.Subscribe(subject, handler)
		if err == nil {
			err = sub.SetPendingLimits(16, 16*netbirdcommand.MaxMessage)
		}
		if err != nil {
			if sub != nil {
				_ = sub.Unsubscribe()
			}
			for _, owned := range s.subscriptions {
				_ = owned.Unsubscribe()
			}
			s.subscriptions = nil
			return ErrActionUnconfirmed
		}
		s.subscriptions = append(s.subscriptions, sub)
	}
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	if connection.FlushWithContext(ctx) != nil {
		for _, sub := range s.subscriptions {
			_ = sub.Unsubscribe()
		}
		s.subscriptions = nil
		return ErrActionUnconfirmed
	}
	s.connection = connection
	return nil
}

func (s *DurableService) admit(binding *netbirdServiceBinding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil || binding == nil || s.connection == nil || s.connection != binding.connection || s.binding != binding {
		return false
	}
	s.work.Add(1)
	return true
}

func (s *DurableService) handler(control bool, subject string, binding *netbirdServiceBinding) nats.MsgHandler {
	return func(msg *nats.Msg) {
		if msg == nil {
			return
		}
		reject := func() { _ = msg.Respond([]byte("NetBird command is unavailable")) }
		if msg.Subject != subject || msg.Reply == "" || !s.admit(binding) {
			reject()
			return
		}
		defer s.work.Done()
		if control {
			c, err := netbirdcommand.DecodeControl(msg.Data)
			if err != nil || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
				reject()
				return
			}
			ctx, cancel := context.WithDeadline(s.ctx, c.ExpiresAt)
			defer cancel()
			var r netbirdcommand.ControlResponse
			if c.Kind == "preparation-state" || c.Kind == "installation-state" {
				r = s.preparationState(c)
			} else {
				r, err = s.journal.Control(ctx, msg.Data)
			}
			if err != nil {
				reject()
				return
			}
			data, err := netbirdcommand.EncodeControlResponse(c, r)
			if err != nil {
				reject()
				return
			}
			_ = msg.Respond(data)
			return
		}
		c, err := netbirdcommand.Decode(msg.Data)
		if err != nil || !c.Executable(s.identity, time.Now()) || c.ExpiresAt.After(s.expires) {
			reject()
			return
		}
		r, err := s.executor.Execute(s.ctx, msg.Data)
		if err != nil {
			reject()
			return
		}
		data, err := netbirdcommand.EncodeReceipt(r)
		if err != nil {
			reject()
			return
		}
		_ = msg.Respond(data)
	}
}

func (s *DurableService) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		for _, sub := range s.subscriptions {
			_ = sub.Unsubscribe()
		}
		s.subscriptions = nil
		s.connection = nil
		s.binding = nil
		s.mu.Unlock()
		s.work.Wait()
		s.closeErr = s.journal.Close()
		if s.preparation != nil && s.preparation.poisoned {
			s.closeErr = ErrActionUnconfirmed
		}
	})
	return s.closeErr
}
