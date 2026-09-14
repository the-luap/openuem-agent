package localready

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

type Server struct {
	identity            Identity
	signer              nkeys.KeyPair
	directory           *linuxReadyDirectory
	lock                *os.File
	address             string
	addressStamp        unix.Stat_t
	socket              unix.Stat_t
	listener            *net.UnixListener
	ctx                 context.Context
	cancel              context.CancelFunc
	ready               atomic.Bool
	work                sync.WaitGroup
	mu                  sync.Mutex
	resourceMu          sync.RWMutex
	connections         map[*net.UnixConn]struct{}
	stopOnce, closeOnce sync.Once
	stopAfter           func() bool
	afterDone, closed   chan struct{}
	closeErr            error
}

// Listen retains protected Linux identity ancestry and serves only kernel-proven
// root peers. The caller owns service exclusion and lends its signer until Close.
func Listen(ctx context.Context, path string, identity Identity, signer nkeys.KeyPair) (_ *Server, resultErr error) {
	if ctx == nil || !identity.Valid() || signer == nil || os.Geteuid() != 0 {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	public, err := signer.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return nil, ErrUnavailable
	}
	directory, err := openLinuxReadyDirectory(path)
	if err != nil {
		return nil, err
	}
	s := &Server{identity: identity, signer: signer, directory: directory, connections: make(map[*net.UnixConn]struct{}), afterDone: make(chan struct{}), closed: make(chan struct{})}
	defer func() {
		if resultErr != nil {
			if s.listener != nil {
				s.listener.Close()
			}
			if s.socket.Ino != 0 {
				_ = directory.removeSocket(s.address, s.socket)
			}
			if s.lock != nil {
				s.lock.Close()
			}
			directory.close()
		}
	}()
	s.lock, err = directory.openLock()
	if err != nil {
		return nil, err
	}
	if unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, ErrConflict
	}
	s.address, err = directory.address(true)
	if err != nil {
		return nil, err
	}
	s.addressStamp, err = directory.entry(addressName)
	if err != nil || !linuxReadyPrivate(s.addressStamp) {
		return nil, ErrConflict
	}
	socketPath := linuxReadySocketPath(directory, s.address)
	if !s.unchanged() {
		return nil, ErrUnavailable
	}
	if stale, err := directory.entry(s.address); err == nil {
		if !linuxReadySocket(stale) {
			return nil, ErrConflict
		}
		probe, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "unix", socketPath)
		if err == nil {
			probe.Close()
			return nil, ErrConflict
		}
		if !errors.Is(err, unix.ECONNREFUSED) || directory.removeSocket(s.address, stale) != nil {
			return nil, ErrConflict
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// This internally generated procfs alias binds inside the retained directory
	// even if a privileged actor concurrently renames its canonical namespace.
	s.listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, ErrUnavailable
	}
	s.listener.SetUnlinkOnClose(false)
	if unix.Fstatat(int(directory.root().Fd()), s.address, &s.socket, unix.AT_SYMLINK_NOFOLLOW) != nil || s.socket.Uid != 0 || s.socket.Mode&unix.S_IFMT != unix.S_IFSOCK || s.socket.Nlink != 1 {
		return nil, ErrUnavailable
	}
	if unix.Fchmodat(int(directory.root().Fd()), s.address, 0600, 0) != nil || !s.unchanged() {
		return nil, ErrUnavailable
	}
	current, err := directory.entry(s.address)
	if err != nil || !linuxReadySocket(current) || current.Dev != s.socket.Dev || current.Ino != s.socket.Ino {
		return nil, ErrConflict
	}
	s.socket = current
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.work.Add(1)
	s.stopAfter = context.AfterFunc(s.ctx, func() { s.stopNetwork(); close(s.afterDone) })
	go s.serve()
	return s, nil
}

func (s *Server) unchanged() bool {
	s.resourceMu.RLock()
	defer s.resourceMu.RUnlock()
	if !s.directory.valid() || !s.directory.matches(lockName, s.lock) {
		return false
	}
	address, err := s.directory.address(false)
	if err != nil || address != s.address {
		return false
	}
	stamp, err := s.directory.entry(addressName)
	if err != nil || !sameLinuxReadyStamp(stamp, s.addressStamp) {
		return false
	}
	if s.socket.Ino != 0 {
		current, err := s.directory.entry(s.address)
		return err == nil && linuxReadySocket(current) && current.Dev == s.socket.Dev && current.Ino == s.socket.Ino
	}
	return true
}

func (s *Server) MarkReady() error {
	if s == nil || s.ctx.Err() != nil || !s.identity.Valid() || !s.unchanged() {
		return ErrUnavailable
	}
	s.ready.Store(true)
	return nil
}

func (s *Server) serve() {
	defer s.work.Done()
	slots := make(chan struct{}, 8)
	tokens, last := float64(8), time.Now()
	for {
		connection, err := s.listener.AcceptUnix()
		if err != nil {
			return
		}
		now := time.Now()
		tokens = min(float64(8), tokens+now.Sub(last).Seconds()*8)
		last = now
		if tokens < 1 {
			connection.Close()
			continue
		}
		tokens--
		if _, err := linuxReadyPeer(connection); err != nil {
			connection.Close()
			continue
		}
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
			if connection.SetDeadline(time.Now().Add(exchangeTimeout)) != nil || !s.unchanged() || s.ctx.Err() != nil {
				return
			}
			_ = replyWithAdmission(connection, s.identity, s.signer, os.Getpid(), s.ready.Load(), func() error {
				if s.ctx.Err() != nil || !s.unchanged() {
					return ErrUnavailable
				}
				return nil
			})
		}()
	}
}

func (s *Server) stopNetwork() {
	s.stopOnce.Do(func() {
		s.ready.Store(false)
		s.listener.Close()
		s.mu.Lock()
		for connection := range s.connections {
			connection.Close()
		}
		s.mu.Unlock()
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
		s.resourceMu.Lock()
		defer s.resourceMu.Unlock()
		s.closeErr = s.directory.removeSocket(s.address, s.socket)
		if err := s.lock.Close(); s.closeErr == nil {
			s.closeErr = err
		}
		if err := s.directory.close(); s.closeErr == nil {
			s.closeErr = err
		}
		s.signer = nil
	})
	<-s.closed
	return s.closeErr
}

func Probe(ctx context.Context, path string, identity Identity, publicKey string) error {
	return probeLinux(ctx, path, identity, publicKey, 0)
}

// ProbeProcess additionally requires the system manager's observed main PID.
// The controller must compare PID, invocation and start time again after this
// exchange; a socket owner alone does not identify the registered invocation.
func ProbeProcess(ctx context.Context, path string, identity Identity, publicKey string, pid uint32) error {
	if pid <= 1 || pid > 1<<31-1 {
		return ErrUnavailable
	}
	return probeLinux(ctx, path, identity, publicKey, pid)
}

func probeLinux(ctx context.Context, path string, identity Identity, publicKey string, expectedPID uint32) (resultErr error) {
	if ctx == nil || !identity.Valid() || os.Geteuid() != 0 {
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
	directory, err := openLinuxReadyDirectory(path)
	if err != nil {
		return err
	}
	defer directory.close()
	address, err := directory.address(false)
	if err != nil {
		return err
	}
	endpoint, err := directory.entry(address)
	if err != nil {
		return ErrUnavailable
	}
	if !linuxReadySocket(endpoint) {
		return ErrConflict
	}
	socketPath := linuxReadySocketPath(directory, address)
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return ErrUnavailable
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	if connection.SetDeadline(deadline) != nil {
		return ErrUnavailable
	}
	pid, err := linuxReadyPeer(connection.(*net.UnixConn))
	if err != nil || !directory.valid() {
		return ErrConflict
	}
	if expectedPID != 0 && uint32(pid) != expectedPID {
		return ErrConflict
	}
	if err := exchange(ctx, connection, identity, publicKey, pid); err != nil {
		return err
	}
	current, err := directory.entry(address)
	currentAddress, addressErr := directory.address(false)
	if err != nil || addressErr != nil || currentAddress != address || !linuxReadySocket(current) || current.Dev != endpoint.Dev || current.Ino != endpoint.Ino {
		return ErrConflict
	}
	return nil
}

func linuxReadyPeer(connection *net.UnixConn) (int, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, ErrUnavailable
	}
	var credentials *unix.Ucred
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil || credentialErr != nil || credentials == nil || credentials.Uid != 0 || credentials.Pid <= 0 {
		return 0, ErrConflict
	}
	return int(credentials.Pid), nil
}

func linuxReadySocketPath(directory *linuxReadyDirectory, address string) string {
	return "/proc/self/fd/" + strconv.Itoa(int(directory.root().Fd())) + "/" + address
}
