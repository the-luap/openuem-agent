package localready

import (
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// readinessPipeListener uses a persistent stop event for pending connections.
// go-winio v0.6.2 can consume its one-shot Close notification while returning a
// different connect error, leaving Close waiting after Accept has already exited.
// Retain its exclusive, disconnected first instance only as a namespace anchor;
// never call Accept on that listener. Connected I/O still uses go-winio.
type readinessPipeListener struct {
	anchor     net.Listener
	name       string
	descriptor *windows.SECURITY_DESCRIPTOR
	stop       windows.Handle
	closed     atomic.Bool
	accept     sync.Mutex
	closeOnce  sync.Once
}

func listenReadinessPipe(name, descriptor string) (net.Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		return nil, err
	}
	anchor, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: descriptor, InputBufferSize: 128, OutputBufferSize: maxResponse + 68})
	if err != nil {
		return nil, err
	}
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		anchor.Close()
		return nil, err
	}
	return &readinessPipeListener{anchor: anchor, name: name, descriptor: sd, stop: stop}, nil
}

func (l *readinessPipeListener) Accept() (net.Conn, error) {
	l.accept.Lock()
	defer l.accept.Unlock()
	for !l.closed.Load() {
		connection, err := l.connect()
		if l.closed.Load() {
			if connection != nil {
				connection.Close()
			}
			return nil, net.ErrClosed
		}
		if err == windows.ERROR_NO_DATA || err == windows.ERROR_PIPE_NOT_CONNECTED || err == windows.ERROR_BROKEN_PIPE {
			// An immediately disconnected client does not stop the listener.
			continue
		}
		return connection, err
	}
	return nil, net.ErrClosed
}

func (l *readinessPipeListener) connect() (_ net.Conn, resultErr error) {
	name, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: l.descriptor}
	handle, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, windows.PIPE_UNLIMITED_INSTANCES, maxResponse+68, 128, 50, &sa)
	runtime.KeepAlive(l.descriptor)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			windows.CloseHandle(handle)
		}
	}()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(event)
	overlapped := windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(handle, &overlapped)
	if err == windows.ERROR_IO_PENDING {
		state, waitErr := windows.WaitForMultipleObjects([]windows.Handle{l.stop, event}, false, windows.INFINITE)
		if waitErr != nil || state != windows.WAIT_OBJECT_0+1 {
			// Cancellation is a request. Always drain the exact outstanding I/O
			// before releasing its handle, event or OVERLAPPED memory.
			_ = windows.CancelIoEx(handle, &overlapped)
		}
		var transferred uint32
		err = windows.GetOverlappedResult(handle, &overlapped, &transferred, true)
		runtime.KeepAlive(&overlapped)
		if waitErr != nil {
			return nil, waitErr
		}
	}
	// A completed or failed connect cannot consume the terminal shutdown state.
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		return nil, err
	}
	file, err := winio.NewOpenFile(handle)
	if err != nil {
		return nil, err
	}
	owned = false
	stream, ok := file.(readinessPipeStream)
	if !ok {
		file.Close()
		return nil, ErrUnavailable
	}
	return &readinessPipeConnection{readinessPipeStream: stream, address: l.anchor.Addr()}, nil
}

func (l *readinessPipeListener) Close() error {
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		_ = windows.SetEvent(l.stop)
		// No pending operation may retain the event after this join. The
		// namespace anchor never accepted connections, so its Close is idle.
		l.accept.Lock()
		defer l.accept.Unlock()
		l.anchor.Close()
		windows.CloseHandle(l.stop)
	})
	return nil
}

func (l *readinessPipeListener) Addr() net.Addr { return l.anchor.Addr() }

type readinessPipeStream interface {
	io.ReadWriteCloser
	Fd() uintptr
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type readinessPipeConnection struct {
	readinessPipeStream
	address net.Addr
}

func (c *readinessPipeConnection) LocalAddr() net.Addr  { return c.address }
func (c *readinessPipeConnection) RemoteAddr() net.Addr { return c.address }
func (c *readinessPipeConnection) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}
