package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/bootstrapinstall"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
)

var errIndividualAgent = errors.New("individual agent configuration or protected identity is unavailable")

// individualRuntime is selected before any shared certificate is read. Its
// immutable identity/scope comes only from the protected enrollment store.
type individualRuntime struct {
	identity        *enrollmentstore.Identity
	directory       string
	readiness       readinessEndpoint
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	connectMu       sync.Mutex
	stopping        bool
	consumerStarted bool
	work            sync.WaitGroup
	brokerClosed    <-chan struct{}
	connection      *nats.Conn
	hardwareVersion atomic.Int32
	recoveryVersion atomic.Int32
	rotationVersion atomic.Int32
	recoveryStarted bool
	recovery        *recoveryClient
	rotation        *rotationClient
	recoveryStore   *enrollmentstore.Store
}

func individualDirectory(mode, directory string) (string, error) {
	switch mode {
	case "", "false":
		if directory != "" {
			return "", errIndividualAgent
		}
		return "", nil
	case "true":
		if directory == "" || !filepath.IsAbs(directory) {
			return "", errIndividualAgent
		}
		return filepath.Clean(directory), nil
	default:
		return "", errIndividualAgent
	}
}

func (a *Agent) configureIndividual(mode, directory string) error {
	return a.configureIndividualWithLease(mode, directory, nil)
}

func (a *Agent) configureIndividualWithLease(mode, directory string, lease individualServiceLease) error {
	directory, err := individualDirectory(mode, directory)
	if err != nil || directory == "" {
		return err
	}
	if lease == nil {
		lease, err = enrollmentstore.AcquireServiceLease(directory)
		if err != nil {
			return errIndividualAgent
		}
		a.ownedServiceLease = lease
	}
	if lease.ValidateDirectory(directory) != nil {
		return errIndividualAgent
	}
	store, err := enrollmentstore.Open(directory)
	if err != nil {
		return errIndividualAgent
	}
	keepStore := false
	defer func() {
		if !keepStore {
			store.Close()
		}
	}()
	binding, err := store.InstallationBinding()
	if err != nil {
		return errIndividualAgent
	}
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	if verifyIndividualInstallation(parent, *binding) != nil {
		return errIndividualAgent
	}
	identity, err := store.Load()
	if err != nil {
		return errIndividualAgent
	}
	if !binding.Matches(identity) {
		identity.Close()
		return errIndividualAgent
	}
	ctx, cancel := context.WithCancel(parent)
	a.individual = &individualRuntime{identity: identity, directory: directory, ctx: ctx, cancel: cancel}
	if binding.Platform == "macos" {
		key, err := store.LoadOrCreateRecipient(identity)
		if err == nil {
			a.individual.recovery, err = newRecoveryClient(identity, key)
			if err != nil {
				key.Close()
			}
		}
		if err != nil {
			log.Print("[ERROR]: protected FileVault validation recipient is unavailable")
		} else {
			journal, journalErr := store.OpenRotationJournal(identity)
			if journalErr == nil {
				a.individual.rotation, journalErr = newRotationClient(a.individual.recovery, journal, directory)
			}
			if journalErr != nil {
				log.Print("[ERROR]: protected FileVault rotation journal is unavailable")
			} else {
				a.individual.recoveryStore, keepStore = store, true
			}
		}
	}
	a.applyIndividualConfig()
	return nil
}

func verifyIndividualInstallation(ctx context.Context, binding enrollmentstore.InstallationBinding) error {
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	if ctx == nil || ctx.Err() != nil || binding.Platform != platform || binding.Architecture != runtime.GOARCH {
		return errIndividualAgent
	}
	if binding.AgentSize == 0 && binding.AgentSHA256 == "" {
		return nil
	}
	image, err := bootstrapinstall.OpenRunningAgent()
	if err != nil {
		return errIndividualAgent
	}
	err = image.VerifyStoredBinding(ctx, binding.AgentSize, binding.AgentSHA256)
	closeErr := image.Close()
	if err != nil || closeErr != nil {
		return errIndividualAgent
	}
	return nil
}

func (a *Agent) applyIndividualConfig() {
	if a.individual == nil {
		return
	}
	identity := a.individual.identity
	a.Config.individual = true
	a.Config.UUID = identity.Response.DeviceID
	a.Config.TenantID = strconv.Itoa(identity.Response.TenantID)
	a.Config.SiteID = strconv.Itoa(identity.Response.SiteID)
	a.Config.NATSServers, a.Config.WebSocketPort = "", ""
	a.Config.AgentCert, a.Config.AgentKey, a.Config.CACert, a.Config.SFTPCert = "", "", "", ""
	a.Config.enforceIndividualTransport()
}

func (c *Config) enforceIndividualTransport() {
	if c.individual {
		c.SFTPDisabled, c.RemoteAssistanceDisabled = true, true
		c.SFTPPort, c.VNCProxyPort = "", ""
	}
}

func (a *Agent) connectBroker() (*nats.Conn, error) {
	if a.individual == nil {
		return openuem.ConnectWithNATS(a.Config.NATSServers, a.Config.AgentCert, a.Config.AgentKey, a.Config.CACert, a.Config.WebSocketPort)
	}
	return a.connectIndividualBroker(nil)
}

// roots is nil in the installed service, which uses OS-managed HTTPS trust.
// The identity's issuing authority must never be used as gateway server trust.
func (a *Agent) connectIndividualBroker(roots *x509.CertPool) (*nats.Conn, error) {
	r := a.individual
	if r == nil {
		return nil, errIndividualAgent
	}
	r.connectMu.Lock()
	defer r.connectMu.Unlock()
	r.mu.Lock()
	if r.stopping {
		r.mu.Unlock()
		return nil, errIndividualAgent
	}
	if r.connection != nil && !r.connection.IsClosed() {
		connection := r.connection
		r.mu.Unlock()
		return connection, nil
	}
	r.work.Add(1)
	r.mu.Unlock()
	defer r.work.Done()
	if r.identity == nil || r.identity.Keys == nil || r.identity.Keys.Certificate == nil {
		return nil, errIndividualAgent
	}
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	i := r.identity
	leaf, err := enrollment.ValidateResponse(i.Response, i.Origin, &i.Keys.Certificate.PublicKey, time.Now())
	if err != nil {
		return nil, errIndividualAgent
	}
	certificate := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: i.Keys.Certificate, Leaf: leaf}
	closed := make(chan struct{})
	once := sync.OnceFunc(func() { close(closed) })
	connection, err := openuem.ConnectAgent(openuem.AgentConnection{
		Endpoint: i.Response.Endpoint, DeviceID: i.Response.DeviceID, BrokerKey: i.Keys.Broker,
		Roots: roots, Certificate: certificate,
		Event: func(state string) {
			if state == "closed" {
				once()
			}
			log.Printf("[INFO]: individual agent broker %s", state)
		},
		ErrorHandler: func(*nats.Conn, *nats.Subscription, error) {
			log.Print("[ERROR]: individual agent messaging or permissions failed")
		},
	})
	if err != nil {
		return nil, errIndividualAgent
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping || r.ctx.Err() != nil {
		connection.Close()
		<-closed
		return nil, errIndividualAgent
	}
	r.brokerClosed = closed
	r.connection = connection
	return connection, nil
}

func (a *Agent) requestBroker(operation string, data []byte, timeout time.Duration) (*nats.Msg, error) {
	if a.NATSConnection == nil {
		return nil, errors.New("agent broker connection is not ready")
	}
	if a.individual == nil {
		return a.NATSConnection.Request(operation, data, timeout)
	}
	subject, err := enrollment.RequestSubject(a.individual.identity.Response.DeviceID, operation)
	if err != nil || len(data) > 8<<20 || timeout <= 0 || timeout > 10*time.Minute {
		return nil, errIndividualAgent
	}
	ctx, cancel := context.WithTimeout(a.individual.ctx, timeout)
	defer cancel()
	message, err := a.NATSConnection.RequestWithContext(ctx, subject, data)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("individual agent request failed")
	}
	return message, nil
}

func (a *Agent) startIndividualConsumer(handler jetstream.MessageHandler) {
	r := a.individual
	r.mu.Lock()
	if r.stopping || r.consumerStarted {
		r.mu.Unlock()
		return
	}
	r.consumerStarted = true
	r.work.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.work.Done()
		js, err := jetstream.New(a.NATSConnection)
		if err != nil {
			log.Print("[ERROR]: individual command client could not start")
			return
		}
		for {
			ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
			consumer, err := openuem.OpenAgentCommandConsumer(ctx, js, r.identity.Response.DeviceID)
			cancel()
			if err == nil {
				consumption, err := consumer.Consume(handler, jetstream.PullMaxMessages(1), jetstream.PullExpiry(25*time.Second), jetstream.ConsumeErrHandler(func(jetstream.ConsumeContext, error) { log.Print("[ERROR]: individual command delivery failed") }))
				if err == nil {
					select {
					case <-r.ctx.Done():
						consumption.Stop()
						<-consumption.Closed()
						return
					case <-consumption.Closed():
					}
				}
			}
			// Issuance can precede server consumer reconciliation. Remain unable
			// to create it and retry only the read operation at a bounded rate.
			select {
			case <-r.ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}
