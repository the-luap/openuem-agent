package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"github.com/open-uem/openuem-agent/internal/localready"
)

type readinessScheduler struct {
	gocron.Scheduler
	start func()
}

func (s *readinessScheduler) Start()          { s.start() }
func (s *readinessScheduler) Shutdown() error { return nil }

type observedReadiness struct {
	mark  func() error
	close func() error
}

func (r *observedReadiness) MarkReady() error { return r.mark() }
func (r *observedReadiness) Close() error     { return r.close() }

func readinessAgent(t *testing.T) *Agent {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	i := &enrollmentstore.Identity{
		Keys:          &enrollment.Keys{Broker: key},
		Response:      enrollment.Response{DeviceID: individualFixtureID, TenantID: 3, SiteID: 4, ExpiresAt: time.Now().Add(time.Hour).UTC()},
		ReleaseDigest: strings.Repeat("a", 64), AgentSize: 42, AgentSHA256: strings.Repeat("b", 64),
	}
	a := &Agent{ctx: ctx, cancel: cancel, individual: &individualRuntime{identity: i, directory: "/private/isolated-identity", ctx: ctx, cancel: cancel}}
	t.Cleanup(a.Stop)
	return a
}

func TestReadinessFollowsSchedulerInitializationAndOwnsPartialResources(t *testing.T) {
	for _, scenario := range []string{"ready", "listen-error", "nil-listener", "mark-error", "cancel-before", "cancel-during-listen", "cancel-during-start", "legacy", "unbound"} {
		t.Run(scenario, func(t *testing.T) {
			a := readinessAgent(t)
			started, listened, marked, closed := false, false, false, false
			a.TaskScheduler = &readinessScheduler{start: func() {
				started = true
				if scenario == "cancel-during-start" {
					a.cancel()
				}
			}}
			if scenario == "legacy" {
				a.individual.identity.Close()
				a.individual = nil
			}
			if scenario == "unbound" {
				a.individual.identity.AgentSize = 0
				a.individual.identity.AgentSHA256 = ""
			}
			if scenario == "cancel-before" {
				a.cancel()
			}
			endpoint := &observedReadiness{
				mark: func() error {
					marked = true
					if !started {
						t.Error("readiness preceded scheduler initialization")
					}
					if err := a.ctx.Err(); err != nil {
						return err
					}
					if scenario == "mark-error" {
						return localready.ErrUnavailable
					}
					return nil
				},
				close: func() error {
					closed = true
					if a.individual.identity.Keys == nil {
						t.Error("keys released before readiness joined")
					}
					return nil
				},
			}
			err := a.startInitializedScheduler(func(ctx context.Context, directory string, got localready.Identity, signer nkeys.KeyPair) (readinessEndpoint, error) {
				listened = true
				i := a.individual.identity
				if started || ctx != a.ctx || directory != a.individual.directory || signer != i.Keys.Broker || got.DeviceID != i.Response.DeviceID || got.TenantID != i.Response.TenantID || got.SiteID != i.Response.SiteID || got.AgentSize != i.AgentSize || got.AgentSHA256 != i.AgentSHA256 || got.ReleaseDigest != i.ReleaseDigest || !got.ExpiresAt.Equal(i.Response.ExpiresAt) {
					t.Error("listener did not receive the protected identity before scheduling")
				}
				if scenario == "listen-error" {
					return endpoint, localready.ErrConflict
				}
				if scenario == "nil-listener" {
					return nil, nil
				}
				if scenario == "cancel-during-listen" {
					a.cancel()
				}
				return endpoint, nil
			})
			wantSuccess := scenario == "ready" || scenario == "legacy" || scenario == "unbound"
			if (err == nil) != wantSuccess {
				t.Fatal("unexpected initialization result", err)
			}
			wantStart := wantSuccess || scenario == "mark-error" || scenario == "cancel-during-start"
			if started != wantStart {
				t.Error("scheduler started after rejected admission")
			}
			if (scenario == "legacy" || scenario == "unbound" || scenario == "cancel-before") && (listened || marked) {
				t.Error("unexpected readiness publication")
			}
			if scenario == "ready" && !marked {
				t.Error("successful initialization did not become ready")
			}
			a.Stop()
			if listened && scenario != "nil-listener" && !closed {
				t.Error("partial readiness endpoint was not joined")
			}
		})
	}
}

func TestAgentStopWaitsForReadinessBeforeReleasingSigningKeys(t *testing.T) {
	a := readinessAgent(t)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseOnce)
	a.individual.readiness = &observedReadiness{close: func() error {
		if !errors.Is(a.ctx.Err(), context.Canceled) {
			t.Error("readiness was joined before cancellation")
		}
		close(entered)
		<-release
		if _, err := a.individual.identity.Keys.Broker.Sign([]byte("owned readiness request")); err != nil {
			t.Error("borrowed key was released before the request finished", err)
		}
		return nil
	}}
	done := make(chan struct{})
	go func() { a.Stop(); close(done) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("readiness shutdown was not reached")
	}
	select {
	case <-done:
		t.Fatal("stop returned before readiness joined")
	default:
	}
	releaseOnce()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stop did not join readiness")
	}
	if a.individual.identity.Keys != nil {
		t.Fatal("joined stop retained the identity")
	}
}
