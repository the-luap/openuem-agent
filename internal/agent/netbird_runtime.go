package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	openuem_nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-agent/internal/commands/netbird"
	"github.com/open-uem/openuem-agent/internal/nativepath"
	"github.com/open-uem/openuem-agent/internal/netbirdjournal"
	openuem_utils "github.com/open-uem/utils"
)

var errNetbirdRuntime = errors.New("NetBird managed execution is unavailable")
var errNetbirdLegacy = errors.New("NetBird mutations require a reviewed command from an updated console")

type nativeNetbirdRuntime struct {
	mu       sync.Mutex
	service  *netbird.DurableService
	identity netbirdcommand.Identity
	closed   bool
}

type netbirdLocalBinding struct {
	Identity                netbirdcommand.Identity
	Directory, Installation string
	ExpiresAt               time.Time
}

func netbirdConfiguredIdentity(c Config) (netbirdcommand.Identity, error) {
	tenant, err := strconv.ParseInt(c.TenantID, 10, 64)
	if err != nil || strconv.FormatInt(tenant, 10) != c.TenantID {
		return netbirdcommand.Identity{}, errNetbirdRuntime
	}
	site, err := strconv.ParseInt(c.SiteID, 10, 64)
	if err != nil || strconv.FormatInt(site, 10) != c.SiteID {
		return netbirdcommand.Identity{}, errNetbirdRuntime
	}
	i := netbirdcommand.Identity{DeviceID: c.UUID, TenantID: tenant, SiteID: site}
	if !i.Valid() {
		return netbirdcommand.Identity{}, errNetbirdRuntime
	}
	return i, nil
}

// netbirdBinding derives immutable journal ownership from the validated native
// installation. Renewable certificate bytes are excluded from Installation but
// retained in the current command identity and service deadline.
func (a *Agent) netbirdBinding(configPath string, now time.Time) (netbirdLocalBinding, error) {
	i, err := netbirdConfiguredIdentity(a.Config)
	if err != nil {
		return netbirdLocalBinding{}, err
	}
	var leaf *x509.Certificate
	var parent, origin, broker string
	if a.individual != nil {
		r := a.individual
		if r.identity == nil || r.identity.Keys == nil || r.identity.Keys.Certificate == nil || r.identity.Keys.Broker == nil || !nativepath.Valid(r.directory) || keyfile.CheckDirectory(r.directory) != nil {
			return netbirdLocalBinding{}, errNetbirdRuntime
		}
		identity := r.identity
		if identity.Response.DeviceID != i.DeviceID || int64(identity.Response.TenantID) != i.TenantID || int64(identity.Response.SiteID) != i.SiteID {
			return netbirdLocalBinding{}, errNetbirdRuntime
		}
		leaf, err = enrollment.ValidateResponse(identity.Response, identity.Origin, &identity.Keys.Certificate.PublicKey, now)
		if err != nil {
			return netbirdLocalBinding{}, errNetbirdRuntime
		}
		broker, err = identity.Keys.Broker.PublicKey()
		if err != nil {
			return netbirdLocalBinding{}, errNetbirdRuntime
		}
		parent, origin = r.directory, identity.Origin
		i.Individual = true
		digest := sha256.Sum256(leaf.Raw)
		i.CertificateHash = hex.EncodeToString(digest[:])
	} else {
		if !nativepath.Valid(configPath) || a.CACert == nil || a.Config.NATSServers == "" || len(a.Config.NATSServers) > 4096 {
			return netbirdLocalBinding{}, errNetbirdRuntime
		}
		parent = filepath.Dir(configPath)
		if checkNetbirdParent(parent) != nil {
			return netbirdLocalBinding{}, errNetbirdRuntime
		}
		pair, err := tls.LoadX509KeyPair(a.Config.AgentCert, a.Config.AgentKey)
		if err != nil || len(pair.Certificate) == 0 {
			return netbirdLocalBinding{}, errNetbirdRuntime
		}
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil || leaf.IsCA {
			return netbirdLocalBinding{}, errNetbirdRuntime
		}
		roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
		roots.AddCert(a.CACert)
		for _, der := range pair.Certificate[1:] {
			intermediate, err := x509.ParseCertificate(der)
			if err != nil {
				return netbirdLocalBinding{}, errNetbirdRuntime
			}
			intermediates.AddCert(intermediate)
		}
		if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return netbirdLocalBinding{}, errNetbirdRuntime
		}
		// A legacy scope comes from installation configuration. Shared transport
		// credentials do not provide an individual cryptographic device identity.
		origin = a.Config.NATSServers
		broker = hex.EncodeToString(a.CACert.RawSubjectPublicKeyInfo)
	}
	if !leaf.NotAfter.After(now) {
		return netbirdLocalBinding{}, errNetbirdRuntime
	}
	stable := i
	stable.CertificateHash = ""
	data, err := json.Marshal(struct {
		Version        int
		Identity       netbirdcommand.Identity
		Origin, Broker string
		PublicKey      []byte
	}{1, stable, origin, broker, leaf.RawSubjectPublicKeyInfo})
	if err != nil || !i.Valid() {
		return netbirdLocalBinding{}, errNetbirdRuntime
	}
	digest := sha256.Sum256(data)
	return netbirdLocalBinding{Identity: i, Directory: filepath.Join(parent, "netbird-journal"), Installation: hex.EncodeToString(digest[:]), ExpiresAt: leaf.NotAfter}, nil
}

func (a *Agent) configureNetbird() error {
	binding, err := a.netbirdBinding(openuem_utils.GetAgentConfigFile(), time.Now())
	if err != nil {
		return errNetbirdRuntime
	}
	boot, err := netbirdjournal.ReadBoot()
	if err != nil {
		return errNetbirdRuntime
	}
	return a.openNetbird(binding, boot)
}

func (a *Agent) openNetbird(binding netbirdLocalBinding, boot netbirdjournal.Boot) error {
	r := &a.netbird
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.service != nil || a.ctx == nil || a.ctx.Err() != nil {
		return errNetbirdRuntime
	}
	journal, err := netbirdjournal.Open(binding.Directory, binding.Installation, binding.Identity, boot)
	if err != nil {
		return errNetbirdRuntime
	}
	service, err := netbird.NewDurableService(a.ctx, journal, binding.Identity, binding.ExpiresAt)
	if err != nil {
		journal.Close()
		return errNetbirdRuntime
	}
	r.service, r.identity = service, binding.Identity
	return nil
}

func (r *nativeNetbirdRuntime) bind(nc *nats.Conn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.service == nil {
		return errNetbirdRuntime
	}
	return r.service.Bind(nc)
}

func (r *nativeNetbirdRuntime) verifyConfig(c Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.service == nil || r.closed {
		return
	}
	i, err := netbirdConfiguredIdentity(c)
	if err != nil || i.DeviceID != r.identity.DeviceID || i.TenantID != r.identity.TenantID || i.SiteID != r.identity.SiteID || c.individual != r.identity.Individual {
		r.closed = true
		_ = r.service.Close()
	}
}

func (r *nativeNetbirdRuntime) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.service != nil {
		_ = r.service.Close()
	}
}

func (a *Agent) rejectLegacyNetbird(operation string) error {
	if a.NATSConnection == nil || !netbirdcommand.ValidDeviceID(a.Config.UUID) {
		return errNetbirdRuntime
	}
	_, err := a.NATSConnection.Subscribe("agent.netbird."+operation+"."+a.Config.UUID, func(msg *nats.Msg) {
		// Old envelopes have no durable identity. Never translate them into a new
		// random command UUID or let them bypass an unresolved journal barrier.
		netbird.Respond(msg, &openuem_nats.Netbird{Error: errNetbirdLegacy.Error()})
	})
	return err
}
