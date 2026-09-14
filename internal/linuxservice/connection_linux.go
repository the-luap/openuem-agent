package linuxservice

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

var ErrManager = errors.New("the protected Linux system service manager is unavailable")
var errUnitNotLoaded = errors.New("the Linux agent service is not loaded in the system manager")

const (
	systemdSocket                       = "/run/systemd/private"
	managerPath         dbus.ObjectPath = "/org/freedesktop/systemd1"
	managerInterface                    = "org.freedesktop.systemd1.Manager"
	managerTimeout                      = 5 * time.Second
	authenticationLimit                 = 16 << 10
)

type systemdConnection struct {
	directory *protectedDirectory
	socket    *os.File
	name      string
	stamp     unix.Stat_t
	wire      *net.UnixConn
	bus       *dbus.Conn
	cancel    context.CancelFunc
	stopAfter func() bool
	afterDone chan struct{}
	mu        sync.Mutex
	closed    bool
	work      sync.WaitGroup
	closeOnce sync.Once
}

// connectSystemd never consults a bus address, executable or environment override.
// The socket must belong to the root system manager, whose kernel PID is 1.
func connectSystemd(ctx context.Context) (*systemdConnection, error) {
	return connectPrivateManager(ctx, systemdSocket, 1)
}

// The alternate path/PID is private to native fixtures; production has no such
// input. Kernel credentials are checked before sending even the auth NUL byte.
func connectPrivateManager(ctx context.Context, socketPath string, pid int32) (_ *systemdConnection, resultErr error) {
	if ctx == nil || os.Geteuid() != 0 || !validPath(socketPath) || pid <= 0 {
		return nil, ErrManager
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := openProtectedDirectory(path.Dir(socketPath))
	if err != nil {
		return nil, ErrManager
	}
	c := &systemdConnection{directory: d, name: path.Base(socketPath), afterDone: make(chan struct{})}
	defer func() {
		if resultErr != nil {
			c.Close()
		}
	}()
	fd, err := unix.Openat(int(d.root().Fd()), c.name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrManager
	}
	c.socket = os.NewFile(uintptr(fd), c.name)
	if unix.Fstat(fd, &c.stamp) != nil || !c.valid() {
		return nil, ErrManager
	}
	alias := "/proc/self/fd/" + strconv.Itoa(int(d.root().Fd())) + "/" + c.name
	dialCtx, cancelDial := context.WithTimeout(ctx, managerTimeout)
	defer cancelDial()
	wire, err := (&net.Dialer{}).DialContext(dialCtx, "unix", alias)
	if err != nil {
		return nil, managerError(ctx, err)
	}
	var ok bool
	c.wire, ok = wire.(*net.UnixConn)
	if !ok {
		wire.Close()
		return nil, ErrManager
	}
	if !managerPeer(c.wire, pid) || !c.valid() {
		return nil, ErrManager
	}
	lifetime, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	// Close the raw socket independently of godbus's output lock: cancellation
	// must interrupt a blocked write before the library can join its shutdown.
	c.stopAfter = context.AfterFunc(lifetime, func() { c.wire.Close(); close(c.afterDone) })
	deadline, _ := dialCtx.Deadline()
	if c.wire.SetDeadline(deadline) != nil {
		return nil, ErrManager
	}
	c.bus, err = dbus.NewConn(&managerTransport{UnixConn: c.wire, remaining: authenticationLimit, ctx: lifetime, deadline: deadline}, dbus.WithContext(lifetime))
	if err != nil {
		return nil, managerError(ctx, err)
	}
	// systemd's private peer uses EXTERNAL authentication and has no bus Hello.
	if err = c.bus.Auth([]dbus.Auth{dbus.AuthExternal("0")}); err != nil {
		return nil, managerError(ctx, err)
	}
	if c.wire.SetDeadline(time.Time{}) != nil || !c.valid() {
		return nil, ErrManager
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

func managerPeer(wire *net.UnixConn, pid int32) bool {
	raw, err := wire.SyscallConn()
	if err != nil {
		return false
	}
	var peer *unix.Ucred
	var peerErr error
	err = raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	return err == nil && peerErr == nil && peer != nil && peer.Uid == 0 && peer.Pid == pid
}

func (c *systemdConnection) valid() bool {
	if c.socket == nil || !c.directory.valid() || c.stamp.Uid != 0 || c.stamp.Nlink != 1 || c.stamp.Mode&unix.S_IFMT != unix.S_IFSOCK || c.stamp.Mode&07000 != 0 {
		return false
	}
	var held, actual unix.Stat_t
	return unix.Fstat(int(c.socket.Fd()), &held) == nil && unix.Fstatat(int(c.directory.root().Fd()), c.name, &actual, unix.AT_SYMLINK_NOFOLLOW) == nil && sameStamp(held, c.stamp) && sameStamp(actual, c.stamp)
}

// call is internal plumbing, not an arbitrary public D-Bus API. Method-specific
// controller operations must admit unit ownership before invoking mutations.
func (c *systemdConnection) call(ctx context.Context, object dbus.ObjectPath, method string, args ...any) ([]any, error) {
	if ctx == nil {
		return nil, ErrManager
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrManager
	}
	c.work.Add(1)
	c.mu.Unlock()
	defer c.work.Done()
	if !c.valid() {
		return nil, ErrManager
	}
	bounded, cancel := context.WithTimeout(ctx, managerTimeout)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(bounded, func() { c.wire.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	reply := c.bus.Object("org.freedesktop.systemd1", object).CallWithContext(bounded, method, dbus.FlagNoAutoStart, args...)
	if err := bounded.Err(); err != nil {
		return nil, err
	}
	if !c.valid() {
		return nil, ErrManager
	}
	if reply.Err != nil {
		var remote dbus.Error
		if object == managerPath && method == managerInterface+".GetUnit" && errors.As(reply.Err, &remote) && remote.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return nil, errUnitNotLoaded
		}
		return nil, managerError(ctx, reply.Err)
	}
	return reply.Body, nil
}

func managerError(ctx context.Context, _ error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Do not expose peer-controlled error bodies, socket names or native details.
	return ErrManager
}

func (c *systemdConnection) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		if c.cancel != nil {
			c.cancel()
		}
		if c.wire != nil {
			c.wire.Close()
		}
		if c.bus != nil {
			c.bus.Close()
		}
		if c.stopAfter != nil && !c.stopAfter() {
			<-c.afterDone
		}
		c.work.Wait()
		if c.socket != nil {
			c.socket.Close()
		}
		c.directory.close()
	})
	return nil
}

// godbus starts its binary reader inside Auth. Flip mode at the outgoing BEGIN
// before that goroutine starts; cap all incoming auth bytes, including lines
// without terminators, independently of the handshake deadline.
type managerTransport struct {
	*net.UnixConn
	binary    atomic.Bool
	remaining int
	ctx       context.Context
	deadline  time.Time
	frame     []byte // owned by the single binary reader
}

func (t *managerTransport) Read(p []byte) (int, error) {
	if t.binary.Load() {
		return t.readFrame(p)
	}
	if t.remaining == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if len(p) > t.remaining {
		p = p[:t.remaining]
	}
	n, err := t.UnixConn.Read(p)
	t.remaining -= n
	return n, err
}

func (t *managerTransport) Write(p []byte) (int, error) {
	wasBinary := t.binary.Load()
	begin := !wasBinary && bytes.Equal(p, []byte("BEGIN\r\n"))
	if begin {
		t.binary.Store(true)
	}
	if wasBinary {
		if err := t.UnixConn.SetWriteDeadline(time.Now().Add(managerTimeout)); err != nil {
			return 0, err
		}
	}
	n, err := t.UnixConn.Write(p)
	if err == nil && begin && n == len(p) {
		err = t.drainAuthentication()
	}
	return n, err
}

// Some systemd peers can leave a first binary message in their auth buffer when
// recvmsg consumes it together with BEGIN, then wait for another socket event.
// Wait for the kernel to report that BEGIN has actually been consumed before
// godbus may send binary messages. This adds no protocol bytes or method call,
// and shares the existing authentication deadline and cancellation lifetime.
func (t *managerTransport) drainAuthentication() error {
	if t.ctx == nil || t.deadline.IsZero() {
		return ErrManager
	}
	raw, err := t.UnixConn.SyscallConn()
	if err != nil {
		return ErrManager
	}
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if err := t.ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(t.deadline) {
			return context.DeadlineExceeded
		}
		var queued int
		var queueErr error
		if err := raw.Control(func(fd uintptr) { queued, queueErr = unix.IoctlGetInt(int(fd), unix.TIOCOUTQ) }); err != nil || queueErr != nil || queued < 0 {
			return ErrManager
		}
		if queued == 0 {
			return nil
		}
		select {
		case <-t.ctx.Done():
			return t.ctx.Err()
		case <-tick.C:
		}
	}
}
