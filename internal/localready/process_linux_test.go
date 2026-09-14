package localready

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestLinuxReadinessBindsObservedServiceProcess(t *testing.T) {
	path := linuxReadyFixture(t)
	key, public := fixtureKey(t)
	identity := fixtureIdentity()
	s, err := Listen(context.Background(), path, identity, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pid := uint32(os.Getpid())
	if err := ProbeProcess(t.Context(), path, identity, public, pid); !errors.Is(err, ErrNotReady) {
		t.Fatal("matching process skipped initialization admission", err)
	}
	if err := s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if err := ProbeProcess(t.Context(), path, identity, public, pid); err != nil {
		t.Fatal("matching observed service process was rejected", err)
	}
	if err := ProbeProcess(t.Context(), path, identity, public, pid+1); !errors.Is(err, ErrConflict) {
		t.Fatal("valid identity from another process was accepted", err)
	}
	for _, invalid := range []uint32{0, 1, 1 << 31, ^uint32(0)} {
		if err := ProbeProcess(t.Context(), path, identity, public, invalid); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid manager process observation was accepted", invalid, err)
		}
	}
	other := identity
	other.SiteID++
	if err := ProbeProcess(t.Context(), path, other, public, pid); !errors.Is(err, ErrConflict) {
		t.Fatal("matching PID bypassed device identity admission", err)
	}
}
