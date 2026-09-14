package linuxservice

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestLinuxManagerWaitsForAuthenticationConsumption(t *testing.T) {
	for _, scenario := range []string{"consumed", "canceled", "deadline", "closed"} {
		t.Run(scenario, func(t *testing.T) {
			root := managerFixture(t)
			release := make(chan struct{})
			peer := newManagerPeer(t, root, func(wire *net.UnixConn) error {
				<-release
				if scenario != "consumed" {
					return nil
				}
				var begin [7]byte
				if _, err := io.ReadFull(wire, begin[:]); err != nil {
					return err
				}
				if string(begin[:]) != "BEGIN\r\n" {
					return errors.New("authentication barrier changed the protocol bytes")
				}
				// Keep the peer alive until the client observes kernel consumption.
				_, err := wire.Read(begin[:])
				if !errors.Is(err, io.EOF) {
					return errors.New("authentication barrier sent unexpected extra bytes")
				}
				return nil
			})
			wire, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: peer.path, Net: "unix"})
			if err != nil {
				close(release)
				t.Fatal(err)
			}
			defer wire.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			transport := &managerTransport{UnixConn: wire, ctx: ctx, deadline: time.Now().Add(200 * time.Millisecond)}
			done := make(chan error, 1)
			go func() {
				n, err := transport.Write([]byte("BEGIN\r\n"))
				if n != 7 {
					err = errors.New("authentication barrier did not write the complete marker")
				}
				done <- err
			}()
			select {
			case err := <-done:
				close(release)
				t.Fatal("authentication completed before the peer consumed BEGIN", err)
			case <-time.After(30 * time.Millisecond):
			}
			if scenario == "consumed" {
				close(release)
			} else {
				defer close(release)
			}
			want := error(nil)
			switch scenario {
			case "canceled":
				want = context.Canceled
				cancel()
			case "deadline":
				want = context.DeadlineExceeded
			case "closed":
				want = ErrManager
				wire.Close()
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatal("authentication drain lost its completion or interruption", err)
				}
			case <-time.After(time.Second):
				cancel()
				wire.Close()
				<-done
				t.Fatal("authentication drain did not join within its bound")
			}
		})
	}
}
