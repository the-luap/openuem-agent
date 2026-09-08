package enrollmentstore

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
)

func TestInstalledEnrollmentChecksAdmissionAtEveryPublicationBoundary(t *testing.T) {
	for _, failure := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			backend := newMemoryBackend(t)
			store := &Store{backend: backend}
			issuer := newFixtureIssuer(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request enrollment.Request
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				response, err := issuer.claim("https://"+r.Host, request)
				if err != nil {
					t.Error(err)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			config := testBootstrap()
			config.Origin = server.URL
			verified := signedConfigurationWithAgentFixture(t, config, true)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			denied := errors.New("isolated native admission failed")
			checks := 0
			admit := func(context.Context) error {
				checks++
				if checks == failure {
					return denied
				}
				return nil
			}
			identity, err := store.EnrollInstalled(context.Background(), verified, config.DeviceName, roots, admit)
			if identity != nil || !errors.Is(err, denied) || checks != failure {
				t.Fatal("failed admission returned an identity", err, checks)
			}
			expectedState := ErrPending
			if failure == 1 {
				expectedState = ErrMissing
			}
			if identity, err := store.Load(); identity != nil || !errors.Is(err, expectedState) {
				t.Fatal("failed admission changed the expected durable state", err)
			}
			issuer.mu.Lock()
			requests, binding := issuer.requests, issuer.binding
			issuer.mu.Unlock()
			if (failure < 3 && requests != 0) || (failure == 3 && requests != 1) {
				t.Fatal("admission ran after the wrong network boundary", requests)
			}
			// Recovery uses the same pending keys even when the first server
			// response was valid but local admission prevented publication.
			allow := func(context.Context) error { return nil }
			identity, err = store.EnrollInstalled(context.Background(), verified, config.DeviceName, roots, allow)
			if err != nil {
				t.Fatal("admission recovery failed", err)
			}
			identity.Close()
			issuer.mu.Lock()
			if issuer.requests != requests+1 || (binding != "" && issuer.binding != binding) {
				t.Error("recovery replaced an issued key binding")
			}
			issuer.mu.Unlock()
			// An already stored identity is also checked after loading; a
			// repeat command cannot skip the native admission requirement.
			checks = 0
			identity, err = store.EnrollInstalled(context.Background(), verified, config.DeviceName, roots, func(context.Context) error {
				checks++
				if checks == 2 {
					return denied
				}
				return nil
			})
			if identity != nil || !errors.Is(err, denied) || checks != 2 {
				t.Fatal("ready identity bypassed admission", err, checks)
			}
			issuer.mu.Lock()
			if issuer.requests != requests+1 {
				t.Error("ready state sent another claim")
			}
			issuer.mu.Unlock()
		})
	}
}

func TestInstalledEnrollmentRequiresAnExecutableBindingAndAdmission(t *testing.T) {
	backend := newMemoryBackend(t)
	store := &Store{backend: backend}
	config := testBootstrap()
	preview := signedConfigurationFixture(t, config)
	called := false
	admit := func(context.Context) error { called = true; return nil }
	if _, err := store.EnrollInstalled(context.Background(), preview, "", nil, admit); !errors.Is(err, artifacts.ErrAgentBinding) || called {
		t.Fatal("preview release without an executable binding reached admission", err)
	}
	verified := signedConfigurationWithAgentFixture(t, config, true)
	if _, err := store.EnrollInstalled(context.Background(), verified, "", nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing native admission was accepted", err)
	}
	if _, err := store.EnrollInstalled(nil, verified, "", nil, admit); !errors.Is(err, ErrUnavailable) || called {
		t.Fatal("nil context reached admission", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.EnrollInstalled(ctx, verified, "", nil, admit); !errors.Is(err, context.Canceled) || called {
		t.Fatal("canceled enrollment reached admission", err)
	}
	if len(backend.records) != 0 {
		t.Fatal("invalid installed enrollment persisted state")
	}
}
