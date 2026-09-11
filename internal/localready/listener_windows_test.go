package localready

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

func TestNativeWindowsReadinessListenerShutdownSurvivesDisconnectedClients(t *testing.T) {
	directory := privateReadinessDirectory(t)
	name, address, err := windowsPipeAddress(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer address.Close()
	for _, mode := range []string{"idle", "pending", "disconnected"} {
		t.Run(mode, func(t *testing.T) {
			for iteration := range 32 {
				listener, err := listenReadinessPipe(name, "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
				if err != nil {
					t.Fatal("owned namespace was not released after joined shutdown", iteration, err)
				}
				accepted := make(chan error, 1)
				if mode != "idle" {
					go func() {
						for {
							connection, err := listener.Accept()
							if err != nil {
								accepted <- err
								return
							}
							connection.Close()
						}
					}()
					if mode == "disconnected" {
						ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
						connection, dialErr := winio.DialPipeAccess(ctx, name, pipeClientAccess)
						cancel()
						if dialErr != nil {
							listener.Close()
							t.Fatal(dialErr)
						}
						connection.Close()
					} else {
						// Vary shutdown against event creation and pending connection.
						time.Sleep(time.Duration(iteration%4) * time.Millisecond)
					}
				}
				closed := make(chan struct{})
				go func() {
					// Concurrent and repeated Close must join the same terminal state.
					var work sync.WaitGroup
					for range 2 {
						work.Go(func() { listener.Close() })
					}
					work.Wait()
					listener.Close()
					close(closed)
				}()
				select {
				case <-closed:
				case <-time.After(3 * time.Second):
					t.Fatal("disconnected client consumed listener shutdown", iteration)
				}
				if mode != "idle" {
					select {
					case err := <-accepted:
						if !errors.Is(err, net.ErrClosed) {
							t.Fatal("connect completion overrode terminal shutdown", err)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("listener returned before joining pending acceptance")
					}
				}
				if connection, err := listener.Accept(); connection != nil || !errors.Is(err, net.ErrClosed) {
					t.Fatal("closed listener reopened acceptance", err)
				}
			}
		})
	}
}
