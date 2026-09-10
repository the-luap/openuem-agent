package localready

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/windows"
)

const pipeClientAccess = (windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE) &^ windows.FILE_APPEND_DATA
const systemPipeDescriptor = "O:SYG:SYD:P(A;;GA;;;SY)(A;;0x12019b;;;BA)"

type Server struct {
	identity            Identity
	signer              nkeys.KeyPair
	ctx                 context.Context
	cancel              context.CancelFunc
	listener            net.Listener
	directory, address  *os.File
	ready               atomic.Bool
	work                sync.WaitGroup
	mu                  sync.Mutex
	connections         map[net.Conn]struct{}
	stopOnce, closeOnce sync.Once
	stopAfter           func() bool
	afterDone, closed   chan struct{}
}

func windowsPrivilegedToken(token windows.Token, systemOnly bool) bool {
	user, err := token.GetTokenUser()
	return err == nil && (user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) || (!systemOnly && token.IsElevated()))
}

// Listen serves only the installed Local System agent. The protocol and signer
// ownership are shared with macOS; transport is a private local-only named pipe.
func Listen(ctx context.Context, directory string, identity Identity, signer nkeys.KeyPair) (*Server, error) {
	return listenWindows(ctx, directory, identity, signer, false)
}

// The non-System option is unexported and used only by isolated native tests.
// The public entry point and activation probe always require Local System.
func listenWindows(ctx context.Context, directory string, identity Identity, signer nkeys.KeyPair, allowAdminServer bool) (_ *Server, resultErr error) {
	if ctx == nil || !nativepath.Valid(directory) || !identity.valid() || signer == nil || !windowsPrivilegedToken(windows.GetCurrentProcessToken(), !allowAdminServer) {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	public, err := signer.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return nil, ErrUnavailable
	}
	s := &Server{identity: identity, signer: signer, connections: make(map[net.Conn]struct{}), afterDone: make(chan struct{}), closed: make(chan struct{})}
	s.directory, err = openWindowsPrivate(directory, true)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() {
		if resultErr != nil {
			if s.listener != nil {
				s.listener.Close()
			}
			if s.address != nil {
				s.address.Close()
			}
			s.directory.Close()
		}
	}()
	name, address, err := windowsPipeAddress(directory, true)
	if err != nil {
		return nil, err
	}
	s.address = address
	if !s.unchanged() {
		return nil, ErrConflict
	}
	descriptor := systemPipeDescriptor
	if allowAdminServer {
		descriptor = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"
	}
	// go-winio reserves the first instance exclusively and rejects remote
	// clients. No existing endpoint is reclaimed or disconnected by admission.
	s.listener, err = winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: descriptor, InputBufferSize: 128, OutputBufferSize: maxResponse + 68})
	if err != nil {
		return nil, ErrConflict
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.work.Add(1)
	s.stopAfter = context.AfterFunc(s.ctx, func() { s.stopNetwork(); close(s.afterDone) })
	go s.serve()
	return s, nil
}

func (s *Server) unchanged() bool { return sameWindowsPath(s.directory) && sameWindowsPath(s.address) }

func (s *Server) MarkReady() error {
	if s == nil || s.ctx.Err() != nil || !s.identity.valid() || !s.unchanged() {
		return ErrUnavailable
	}
	s.ready.Store(true)
	return nil
}

func duplicatePipeHandle(connection net.Conn) (windows.Handle, error) {
	file, ok := connection.(interface{ Fd() uintptr })
	if !ok {
		return 0, ErrUnavailable
	}
	var handle windows.Handle
	process := windows.CurrentProcess()
	if windows.DuplicateHandle(process, windows.Handle(file.Fd()), process, &handle, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
		return 0, ErrUnavailable
	}
	return handle, nil
}

func windowsPipePeer(handle windows.Handle, server bool, systemOnly bool) (uint32, windows.Handle, error) {
	var pid uint32
	var err error
	if server {
		err = windows.GetNamedPipeServerProcessId(handle, &pid)
	} else {
		err = windows.GetNamedPipeClientProcessId(handle, &pid)
	}
	if err != nil || pid == 0 {
		return 0, 0, ErrConflict
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return 0, 0, ErrConflict
	}
	var token windows.Token
	err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token)
	if err != nil {
		windows.CloseHandle(process)
		return 0, 0, ErrConflict
	}
	accepted := windowsPrivilegedToken(token, systemOnly)
	token.Close()
	if !accepted || !windowsProcessAlive(process) {
		windows.CloseHandle(process)
		return 0, 0, ErrConflict
	}
	return pid, process, nil
}

func windowsProcessAlive(process windows.Handle) bool {
	status, err := windows.WaitForSingleObject(process, 0)
	return err == nil && status == uint32(windows.WAIT_TIMEOUT)
}

func (s *Server) serve() {
	defer s.work.Done()
	slots := make(chan struct{}, 8)
	tokens, last := float64(8), time.Now()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		now := time.Now()
		tokens += now.Sub(last).Seconds() * 8
		if tokens > 8 {
			tokens = 8
		}
		last = now
		if tokens < 1 {
			connection.Close()
			continue
		}
		tokens--
		handle, err := duplicatePipeHandle(connection)
		if err != nil {
			connection.Close()
			continue
		}
		_, process, err := windowsPipePeer(handle, false, false)
		windows.CloseHandle(handle)
		if err != nil {
			connection.Close()
			continue
		}
		windows.CloseHandle(process)
		select {
		case slots <- struct{}{}:
		default:
			connection.Close()
			continue
		}
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			<-slots
			connection.Close()
			return
		}
		s.connections[connection] = struct{}{}
		s.work.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.work.Done()
			defer func() { connection.Close(); s.mu.Lock(); delete(s.connections, connection); s.mu.Unlock(); <-slots }()
			if connection.SetDeadline(time.Now().Add(exchangeTimeout)) != nil || s.ctx.Err() != nil || !s.unchanged() {
				return
			}
			_ = reply(connection, s.identity, s.signer, os.Getpid(), s.ready.Load())
		}()
	}
}

func (s *Server) stopNetwork() {
	s.stopOnce.Do(func() {
		s.ready.Store(false)
		s.listener.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		for connection := range s.connections {
			connection.Close()
		}
	})
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		defer close(s.closed)
		s.cancel()
		s.stopNetwork()
		if !s.stopAfter() {
			<-s.afterDone
		}
		s.work.Wait()
		s.address.Close()
		s.directory.Close()
		s.signer = nil
	})
	<-s.closed
	return nil
}

func Probe(ctx context.Context, directory string, identity Identity, publicKey string) error {
	return probeWindows(ctx, directory, identity, publicKey, 0, false)
}

// ProbeProcess additionally binds readiness to the SCM-reported service PID.
// Activation checks that same live SCM process again after the signed exchange.
func ProbeProcess(ctx context.Context, directory string, identity Identity, publicKey string, pid uint32) error {
	if pid == 0 {
		return ErrUnavailable
	}
	return probeWindows(ctx, directory, identity, publicKey, pid, false)
}

func probeWindows(ctx context.Context, directory string, identity Identity, publicKey string, expectedPID uint32, allowAdminServer bool) (resultErr error) {
	if ctx == nil || !nativepath.Valid(directory) || !identity.valid() || !windowsPrivilegedToken(windows.GetCurrentProcessToken(), false) {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	defer func() {
		if ctx.Err() != nil {
			resultErr = ctx.Err()
		} else if !time.Now().Before(deadline) {
			resultErr = context.DeadlineExceeded
		}
	}()
	root, err := openWindowsPrivate(directory, true)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Close()
	name, address, err := windowsPipeAddress(directory, false)
	if err != nil {
		return err
	}
	defer address.Close()
	connection, err := winio.DialPipeAccess(ctx, name, pipeClientAccess)
	if err != nil {
		return ErrUnavailable
	}
	defer connection.Close()
	handle, err := duplicatePipeHandle(connection)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if privateWindowsHandle(handle, true, allowAdminServer) != nil {
		return ErrConflict
	}
	pid, process, err := windowsPipePeer(handle, true, !allowAdminServer)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	if expectedPID != 0 && pid != expectedPID {
		return ErrConflict
	}
	if connection.SetDeadline(deadline) != nil {
		return ErrUnavailable
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { connection.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	if err = exchange(ctx, connection, identity, publicKey, int(pid)); err != nil {
		return err
	}
	if !sameWindowsPath(root) || !sameWindowsPath(address) || !windowsProcessAlive(process) || privateWindowsHandle(handle, true, allowAdminServer) != nil {
		return ErrConflict
	}
	return nil
}
