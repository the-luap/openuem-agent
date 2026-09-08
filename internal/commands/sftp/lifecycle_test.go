package sftp

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCanceledFileTransferNeverRetainsAListener(t *testing.T) {
	for range 12 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- New().ServeContext(ctx, "127.0.0.1:0", nil, nil, nil) }()
		// Exercise cancellation before or during initialization. No client connects
		// and no inventory, credentials, or external server is used.
		time.AfterFunc(time.Millisecond, cancel)
		select {
		case err := <-done:
			cancel()
			if !errors.Is(err, context.Canceled) {
				t.Fatal("unexpected file transfer result", err)
			}
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("file transfer listener outlived cancellation")
		}
	}
	if err := New().ServeContext(nil, "127.0.0.1:0", nil, nil, nil); err == nil {
		t.Fatal("nil context accepted")
	}
}
