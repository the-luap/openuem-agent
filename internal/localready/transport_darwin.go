package localready

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/unix"
)

const (
	lockName      = ".openuem-readiness.lock"
	addressName   = ".openuem-readiness.address"
	addressPrefix = "openuem-readiness-v1:"
)

type Server struct {
	identity                  Identity
	signer                    nkeys.KeyPair
	uid                       uint32
	ctx                       context.Context
	cancel                    context.CancelFunc
	listener                  *net.UnixListener
	directory, lock           *os.File
	directoryInfo, socketInfo os.FileInfo
	path, socketPath          string
	ready                     atomic.Bool
	work                      sync.WaitGroup
	mu                        sync.Mutex
	connections               map[*net.UnixConn]struct{}
	stopOnce, closeOnce       sync.Once
	stopAfter                 func() bool
	afterDone, closed         chan struct{}
}

// Listen requires the root-owned private identity directory and a validated
// admitted identity. It borrows the signer until Close has joined all requests.
// The listener begins not-ready; MarkReady follows successful initialization.
func Listen(ctx context.Context, directory string, identity Identity, signer nkeys.KeyPair) (*Server, error) {
	return listen(ctx, directory, identity, signer, 0)
}

func listen(ctx context.Context, directory string, identity Identity, signer nkeys.KeyPair, uid uint32) (_ *Server, err error) {
	if ctx == nil || !nativepath.Valid(directory) || !identity.valid() || signer == nil || uint32(os.Geteuid()) != uid {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	public, err := signer.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return nil, ErrUnavailable
	}
	s := &Server{identity: identity, signer: signer, uid: uid, path: directory, connections: make(map[*net.UnixConn]struct{}), afterDone: make(chan struct{}), closed: make(chan struct{})}
	s.directory, s.directoryInfo, err = openPrivate(directory, true, uid)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() {
		if err != nil {
			if s.listener != nil {
				s.listener.Close()
			}
			if s.lock != nil {
				s.lock.Close()
			}
			s.directory.Close()
		}
	}()
	s.lock, err = openLock(directory, uid)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, ErrConflict
	}
	address, err := socketAddress(directory, uid, true)
	if err != nil {
		return nil, err
	}
	s.socketPath = filepath.Join(directory, address)
	if len(s.socketPath) >= 104 || !s.directoryUnchanged() {
		return nil, ErrUnavailable
	}
	if entry, err := os.Lstat(s.socketPath); err == nil {
		owner, ok := entry.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uid || entry.Mode()&os.ModeSocket == 0 {
			return nil, ErrConflict
		}
		// An active endpoint always wins, including a foreign process. Reclaim
		// only an inactive socket in this installation's immutable random address.
		probe, dialErr := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "unix", s.socketPath)
		if dialErr == nil {
			probe.Close()
			return nil, ErrConflict
		}
		if !errors.Is(dialErr, unix.ECONNREFUSED) {
			return nil, ErrConflict
		}
		current, err := os.Lstat(s.socketPath)
		if err != nil || !os.SameFile(entry, current) || os.Remove(s.socketPath) != nil {
			return nil, ErrConflict
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: s.socketPath, Net: "unix"})
	if err != nil {
		return nil, ErrUnavailable
	}
	s.listener.SetUnlinkOnClose(false)
	s.socketInfo, err = os.Lstat(s.socketPath)
	if err != nil || os.Chmod(s.socketPath, 0600) != nil || !s.directoryUnchanged() {
		s.removeOwnedSocket()
		return nil, ErrUnavailable
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.work.Add(1) // Keep admission counted until Accept can no longer add work.
	s.stopAfter = context.AfterFunc(s.ctx, func() { s.stopNetwork(); close(s.afterDone) })
	go s.serve()
	return s, nil
}

func (s *Server) MarkReady() error {
	if s == nil || s.ctx.Err() != nil || !s.identity.valid() || !s.directoryUnchanged() {
		return ErrUnavailable
	}
	s.ready.Store(true)
	return nil
}

func (s *Server) directoryUnchanged() bool {
	current, err := os.Lstat(s.path)
	if err != nil || !os.SameFile(current, s.directoryInfo) || !private(current, true, s.uid) {
		return false
	}
	if s.lock != nil {
		entry, err := os.Lstat(filepath.Join(s.path, lockName))
		opened, openErr := s.lock.Stat()
		if err != nil || openErr != nil || !os.SameFile(entry, opened) || !private(entry, false, s.uid) {
			return false
		}
	}
	return true
}

func (s *Server) serve() {
	defer s.work.Done()
	slots := make(chan struct{}, 8)
	// Even privileged clients cannot create unbounded signing/worker work.
	tokens, last := float64(8), time.Now()
	for {
		connection, err := s.listener.AcceptUnix()
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
		if _, err := peer(connection, s.uid); err != nil {
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
			if connection.SetDeadline(time.Now().Add(exchangeTimeout)) != nil || !s.directoryUnchanged() || s.ctx.Err() != nil {
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
		for connection := range s.connections {
			connection.Close()
		}
		s.mu.Unlock()
	})
}

func (s *Server) removeOwnedSocket() {
	if s.socketInfo == nil || s.directory == nil {
		return
	}
	owned, ok := s.socketInfo.Sys().(*syscall.Stat_t)
	var current unix.Stat_t
	name := filepath.Base(s.socketPath)
	if ok && unix.Fstatat(int(s.directory.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && current.Dev == owned.Dev && current.Ino == owned.Ino {
		_ = unix.Unlinkat(int(s.directory.Fd()), name, 0)
	}
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
		s.removeOwnedSocket()
		_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
		_ = s.lock.Close()
		_ = s.directory.Close()
		s.signer = nil
	})
	<-s.closed
	return nil
}

func Probe(ctx context.Context, directory string, identity Identity, publicKey string) error {
	return probe(ctx, directory, identity, publicKey, 0)
}

func probe(ctx context.Context, directory string, identity Identity, publicKey string, uid uint32) (resultErr error) {
	if ctx == nil || !nativepath.Valid(directory) || !identity.valid() || uint32(os.Geteuid()) != uid {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	defer func() {
		if resultErr != nil && ctx.Err() != nil {
			resultErr = ctx.Err()
		}
	}()
	root, rootInfo, err := openPrivate(directory, true, uid)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Close()
	address, err := socketAddress(directory, uid, false)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, address)
	if len(path) >= 104 {
		return ErrUnavailable
	}
	endpoint, err := os.Lstat(path)
	if err != nil {
		return ErrUnavailable
	}
	if !privateSocket(endpoint, uid) {
		return ErrConflict
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return ErrUnavailable
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return ErrUnavailable
	}
	pid, err := peer(connection.(*net.UnixConn), uid)
	if err != nil {
		return ErrConflict
	}
	current, err := os.Lstat(directory)
	if err != nil || !os.SameFile(rootInfo, current) || !private(current, true, uid) {
		return ErrConflict
	}
	if err := exchange(ctx, connection, identity, publicKey, pid); err != nil {
		return err
	}
	current, err = os.Lstat(directory)
	currentEndpoint, endpointErr := os.Lstat(path)
	if err != nil || endpointErr != nil || !os.SameFile(rootInfo, current) || !private(current, true, uid) || !os.SameFile(endpoint, currentEndpoint) || !privateSocket(currentEndpoint, uid) {
		return ErrConflict
	}
	return nil
}

func privateSocket(info os.FileInfo, uid uint32) bool {
	if info == nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uid && info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) == 0
}

func peer(connection *net.UnixConn, uid uint32) (int, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, ErrUnavailable
	}
	pid := 0
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil || credentials.Version != 0 || credentials.Uid != uid {
			credentialErr = ErrConflict
			return
		}
		pid, credentialErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil || credentialErr != nil || pid <= 0 {
		return 0, ErrConflict
	}
	return pid, nil
}

func private(info os.FileInfo, directory bool, uid uint32) bool {
	if info == nil || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm()&0077 != 0 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uid && info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) == 0
}

func openPrivate(path string, directory bool, uid uint32) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !private(before, directory, uid) {
		return nil, nil, ErrUnavailable
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), path)
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !private(after, directory, uid) {
		file.Close()
		return nil, nil, ErrUnavailable
	}
	return file, after, nil
}

func openLock(directory string, uid uint32) (*os.File, error) {
	path := filepath.Join(directory, lockName)
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	entry, entryErr := os.Lstat(path)
	if err != nil || entryErr != nil || info.Size() != 0 || !private(info, false, uid) || !os.SameFile(info, entry) {
		file.Close()
		return nil, ErrConflict
	}
	return file, nil
}

func socketAddress(directory string, uid uint32, create bool) (string, error) {
	path := filepath.Join(directory, addressName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) && create {
		data := addressPrefix + uuid.NewString() + "\n"
		temporary := filepath.Join(directory, ".ready-address-"+uuid.NewString()+".tmp")
		file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return "", ErrUnavailable
		}
		owned, _ := file.Stat()
		defer func() {
			if current, err := os.Lstat(temporary); err == nil && owned != nil && os.SameFile(owned, current) {
				_ = os.Remove(temporary)
			}
		}()
		_, err = io.WriteString(file, data)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return "", ErrUnavailable
		}
		if err := os.Link(temporary, path); err != nil && !errors.Is(err, os.ErrExist) {
			return "", ErrUnavailable
		}
		parent, err := os.Open(directory)
		if err != nil {
			return "", ErrUnavailable
		}
		err = parent.Sync()
		closeErr = parent.Close()
		if err != nil || closeErr != nil {
			return "", ErrUnavailable
		}
	}
	file, info, err := openPrivate(path, false, uid)
	if err != nil {
		return "", ErrUnavailable
	}
	defer file.Close()
	if info.Size() != int64(len(addressPrefix)+37) {
		return "", ErrConflict
	}
	data, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil || !strings.HasPrefix(string(data), addressPrefix) || !strings.HasSuffix(string(data), "\n") {
		return "", ErrConflict
	}
	id := strings.TrimSuffix(strings.TrimPrefix(string(data), addressPrefix), "\n")
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id || parsed.Version() != 4 {
		return "", ErrConflict
	}
	return ".ready-" + id + ".sock", nil
}
