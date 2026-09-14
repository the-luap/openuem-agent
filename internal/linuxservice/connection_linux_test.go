package linuxservice

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func managerFixture(t *testing.T) string {
	t.Helper()
	if os.Getenv("OPENUEM_TEST_LINUX_UNITS") != "owned-isolated-units" {
		t.Skip("requires isolated native systemd fixture")
	}
	var fs unix.Statfs_t
	if os.Geteuid() != 0 || os.TempDir() != "/fixture" || unix.Statfs("/fixture", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Fatal("native manager fixture requires owned private tmpfs")
	}
	root, err := os.MkdirTemp("/fixture", "manager-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	return root
}

type managerFixturePeer struct {
	path     string
	listener *net.UnixListener
	mu       sync.Mutex
	active   *net.UnixConn
	closing  bool
	done     chan error
}

func newManagerPeer(t *testing.T, root string, serve func(*net.UnixConn) error) *managerFixturePeer {
	t.Helper()
	d, err := openProtectedDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	alias := "/proc/self/fd/" + strconv.Itoa(int(d.root().Fd())) + "/private"
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: alias, Net: "unix"})
	d.close()
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	p := &managerFixturePeer{path: filepath.Join(root, "private"), listener: l, done: make(chan error, 1)}
	// systemd's private socket can allow all users to connect; trust must come
	// from the kernel peer identity, not permission bits on the socket itself.
	if err := os.Chmod(p.path, 0666); err != nil {
		l.Close()
		t.Fatal(err)
	}
	go func() {
		wire, err := l.AcceptUnix()
		p.mu.Lock()
		if wire != nil {
			p.active = wire
		}
		closing := p.closing
		p.mu.Unlock()
		if wire != nil {
			defer wire.Close()
		}
		if err != nil || closing {
			p.done <- nil
			return
		}
		_ = wire.SetDeadline(time.Now().Add(15 * time.Second))
		p.done <- serve(wire)
	}()
	t.Cleanup(func() {
		p.mu.Lock()
		p.closing = true
		l.Close()
		p.mu.Unlock()
		// Let the peer consume buffered BEGIN/replies and the client's EOF. An
		// immediate fixture-side close would hide or invent protocol failures.
		select {
		case err := <-p.done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			p.mu.Lock()
			if p.active != nil {
				p.active.Close()
			}
			p.mu.Unlock()
			<-p.done
			t.Error("native peer required forced fixture shutdown")
		}
	})
	return p
}

func authenticateManagerPeer(wire *net.UnixConn, challenge bool) (*bufio.Reader, error) {
	return authenticateManagerPeerWithHook(wire, challenge, nil)
}

func authenticateManagerPeerWithHook(wire *net.UnixConn, challenge bool, beforeOK func() error) (*bufio.Reader, error) {
	r := bufio.NewReader(wire)
	b, err := r.ReadByte()
	if err != nil || b != 0 {
		return nil, fmt.Errorf("missing auth NUL: %v", err)
	}
	readLine := func(expected string) error {
		line, err := r.ReadString('\n')
		if err != nil || line != expected {
			return fmt.Errorf("unexpected native auth line %q: %v", line, err)
		}
		return nil
	}
	if err := readLine("AUTH\r\n"); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(wire, "REJECTED EXTERNAL\r\n"); err != nil {
		return nil, err
	}
	if err := readLine("AUTH EXTERNAL\r\n"); err != nil {
		return nil, err
	}
	if challenge {
		if _, err := io.WriteString(wire, "DATA\r\n"); err != nil {
			return nil, err
		}
		if err := readLine("DATA\r\n"); err != nil {
			return nil, err
		}
	}
	if beforeOK != nil {
		if err := beforeOK(); err != nil {
			return nil, err
		}
	}
	if _, err := io.WriteString(wire, "OK 0123456789abcdef0123456789abcdef\r\n"); err != nil {
		return nil, err
	}
	if err := readLine("BEGIN\r\n"); err != nil {
		return nil, err
	}
	return r, nil
}

func sendManagerReply(w io.Writer, call *dbus.Message, errorName string, body ...any) error {
	m := &dbus.Message{Type: dbus.TypeMethodReply, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldReplySerial: dbus.MakeVariant(call.Serial()),
	}, Body: body}
	if len(body) != 0 {
		m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(body...))
	}
	if errorName != "" {
		m.Type = dbus.TypeError
		m.Headers[dbus.FieldErrorName] = dbus.MakeVariant(errorName)
	}
	var encoded bytes.Buffer
	if err := m.EncodeTo(&encoded, binary.LittleEndian); err != nil {
		return err
	}
	data := encoded.Bytes()
	// The codec's constructed message has no exported serial setter. Assign
	// the test peer's serial in the standard fixed D-Bus header after encoding.
	binary.LittleEndian.PutUint32(data[8:12], call.Serial())
	_, err := w.Write(data)
	return err
}

func managerRequest(c *systemdConnection, ctx context.Context) ([]any, error) {
	return c.call(ctx, managerPath, managerInterface+".GetUnit", UnitName)
}

func TestLinuxManagerPrivateAuthenticationAndCalls(t *testing.T) {
	for _, challenge := range []bool{false, true} {
		t.Run(strconv.FormatBool(challenge), func(t *testing.T) {
			root := managerFixture(t)
			// Long canonical paths are safe because only an internally generated
			// descriptor alias is passed to the kernel's short sockaddr_un path.
			root = filepath.Join(root, strings.Repeat("long", 35))
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			expected := dbus.ObjectPath("/org/freedesktop/systemd1/unit/openuem_2dagent_2eservice")
			peer := newManagerPeer(t, root, func(wire *net.UnixConn) error {
				r, err := authenticateManagerPeer(wire, challenge)
				if err != nil {
					return err
				}
				call, err := dbus.DecodeMessage(r)
				if err != nil {
					return err
				}
				if call.Type != dbus.TypeMethodCall || call.Headers[dbus.FieldPath].Value() != managerPath || call.Headers[dbus.FieldInterface].Value() != managerInterface || call.Headers[dbus.FieldMember].Value() != "GetUnit" || len(call.Body) != 1 || call.Body[0] != UnitName || call.Flags&dbus.FlagNoAutoStart == 0 {
					return errors.New("private connection emitted Hello or an unexpected method")
				}
				return sendManagerReply(wire, call, "", expected)
			})
			t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/must-not-use-environment")
			t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/must-not-use-environment")
			c, err := connectPrivateManager(context.Background(), peer.path, int32(os.Getpid()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			body, err := managerRequest(c, context.Background())
			if err != nil || len(body) != 1 || body[0] != expected {
				t.Fatal("private method reply lost", body, err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := managerRequest(c, context.Background()); !errors.Is(err, ErrManager) {
				t.Fatal("closed connection admitted call", err)
			}
			if _, err := os.Lstat(peer.path); err != nil {
				t.Fatal("client removed the manager socket", err)
			}
		})
	}
}

func TestLinuxManagerRejectsPIDBeforeAuthentication(t *testing.T) {
	root := managerFixture(t)
	peer := newManagerPeer(t, root, func(wire *net.UnixConn) error {
		var first [1]byte
		n, err := wire.Read(first[:])
		if n != 0 || !errors.Is(err, io.EOF) {
			return fmt.Errorf("foreign peer received auth bytes: %d %v", n, err)
		}
		return nil
	})
	if c, err := connectPrivateManager(context.Background(), peer.path, 1); c != nil || !errors.Is(err, ErrManager) {
		if c != nil {
			c.Close()
		}
		t.Fatal("ordinary root process admitted as PID 1", err)
	}
}

func TestLinuxManagerRejectsUnsafeAndChangedNamespace(t *testing.T) {
	for _, scenario := range []string{"symlink-parent", "writable-parent", "foreign-parent", "symlink-socket", "foreign-socket", "hardlinked-socket", "replace-parent-before-call", "replace-socket-before-call", "replace-socket-during-reply", "change-parent-during-auth"} {
		t.Run(scenario, func(t *testing.T) {
			root := managerFixture(t)
			dir := filepath.Join(root, "manager")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			requests := make(chan struct{}, 1)
			mutate := func() error {
				switch scenario {
				case "replace-parent-before-call":
					if err := os.Rename(dir, dir+"-retained"); err != nil {
						return err
					}
					return os.Mkdir(dir, 0700)
				case "replace-socket-before-call", "replace-socket-during-reply":
					if err := os.Rename(filepath.Join(dir, "private"), filepath.Join(dir, "retained")); err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(dir, "private"), []byte("foreign socket replacement"), 0600)
				case "change-parent-during-auth":
					return os.Chmod(dir, 0777)
				}
				return nil
			}
			peer := newManagerPeer(t, dir, func(wire *net.UnixConn) error {
				if !strings.Contains(scenario, "before-call") && !strings.Contains(scenario, "during-") {
					var data [1]byte
					n, _ := wire.Read(data[:])
					if n != 0 {
						return errors.New("unsafe namespace received authentication")
					}
					return nil
				}
				var hook func() error
				if scenario == "change-parent-during-auth" {
					hook = mutate
				}
				r, err := authenticateManagerPeerWithHook(wire, false, hook)
				if err != nil {
					return err
				}
				call, err := dbus.DecodeMessage(r)
				if errors.Is(err, io.EOF) {
					return nil
				}
				if err != nil {
					return err
				}
				requests <- struct{}{}
				if scenario == "replace-socket-during-reply" {
					if err := mutate(); err != nil {
						return err
					}
					return sendManagerReply(wire, call, "", dbus.ObjectPath("/owned"))
				}
				return errors.New("changed namespace received a method")
			})
			switch scenario {
			case "symlink-parent":
				if err := os.Rename(dir, dir+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+"-retained", dir); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			case "foreign-parent":
				if err := os.Chown(dir, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "symlink-socket":
				if err := os.Rename(peer.path, peer.path+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(peer.path+"-retained", peer.path); err != nil {
					t.Fatal(err)
				}
			case "foreign-socket":
				if err := os.Chown(peer.path, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "hardlinked-socket":
				if err := os.Link(peer.path, peer.path+"-link"); err != nil {
					t.Fatal(err)
				}
			}
			c, err := connectPrivateManager(context.Background(), peer.path, int32(os.Getpid()))
			if strings.Contains(scenario, "before-call") || scenario == "replace-socket-during-reply" {
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if strings.Contains(scenario, "before-call") {
					if err := mutate(); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := managerRequest(c, context.Background()); !errors.Is(err, ErrManager) {
					t.Fatal("changed namespace admitted", err)
				}
				if scenario != "replace-socket-during-reply" {
					select {
					case <-requests:
						t.Fatal("method sent after namespace replacement")
					default:
					}
				}
			} else if c != nil || !errors.Is(err, ErrManager) {
				if c != nil {
					c.Close()
				}
				t.Fatal("unsafe manager admitted", err)
			}
		})
	}
}

func TestLinuxManagerBoundsAuthenticationAndSanitizesErrors(t *testing.T) {
	for _, scenario := range []string{"unterminated", "malformed", "rejected", "silent", "canceled", "peer-error"} {
		t.Run(scenario, func(t *testing.T) {
			root := managerFixture(t)
			seen := make(chan struct{})
			peer := newManagerPeer(t, root, func(wire *net.UnixConn) error {
				if scenario == "peer-error" {
					r, err := authenticateManagerPeer(wire, false)
					if err != nil {
						return err
					}
					call, err := dbus.DecodeMessage(r)
					if err != nil {
						return err
					}
					return sendManagerReply(wire, call, "org.freedesktop.systemd1.SyntheticFailure", "synthetic-sensitive-peer-diagnostic")
				}
				first := make([]byte, 7)
				if _, err := io.ReadFull(wire, first); err != nil {
					return err
				}
				close(seen)
				switch scenario {
				case "unterminated":
					_, _ = io.WriteString(wire, strings.Repeat("x", authenticationLimit*2))
				case "malformed":
					_, _ = io.WriteString(wire, "synthetic-sensitive-peer-diagnostic\r\n")
				case "rejected":
					_, _ = io.WriteString(wire, "REJECTED DBUS_COOKIE_SHA1\r\n")
				}
				_, _ = io.Copy(io.Discard, wire)
				return nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "canceled" {
				go func() { <-seen; cancel() }()
			}
			start := time.Now()
			c, err := connectPrivateManager(ctx, peer.path, int32(os.Getpid()))
			if scenario == "peer-error" {
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				_, err = managerRequest(c, ctx)
			} else if c != nil {
				c.Close()
				t.Fatal("invalid authentication succeeded")
			}
			if scenario == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation lost", err)
				}
			} else if !errors.Is(err, ErrManager) || strings.Contains(err.Error(), "sensitive") {
				t.Fatal("peer error was not sanitized", err)
			}
			limit := 2 * time.Second
			if scenario == "silent" {
				limit = managerTimeout + 2*time.Second
			}
			if time.Since(start) > limit {
				t.Fatal("authentication did not stay bounded")
			}
		})
	}
}

func TestLinuxManagerCancellationAndJoinedClose(t *testing.T) {
	for _, scenario := range []string{"call-deadline", "lifetime-cancel", "concurrent-close", "blocked-write"} {
		t.Run(scenario, func(t *testing.T) {
			root := managerFixture(t)
			seen := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			peer := newManagerPeer(t, root, func(wire *net.UnixConn) error {
				r, err := authenticateManagerPeer(wire, false)
				if err != nil {
					return err
				}
				if scenario == "blocked-write" {
					// Do not consume binary bytes until the client has interrupted its
					// write. Closing our side here would conceal a shutdown deadlock.
					close(seen)
					<-release
					return nil
				}
				if _, err := dbus.DecodeMessage(r); err != nil {
					return err
				}
				close(seen)
				_, _ = io.Copy(io.Discard, wire)
				return nil
			})
			lifetime, cancelLifetime := context.WithCancel(context.Background())
			defer cancelLifetime()
			c, err := connectPrivateManager(lifetime, peer.path, int32(os.Getpid()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if scenario == "blocked-write" {
				if err := c.wire.SetWriteBuffer(4096); err != nil {
					t.Fatal(err)
				}
			}
			timeout := 100 * time.Millisecond
			if scenario == "lifetime-cancel" || scenario == "concurrent-close" {
				timeout = 5 * time.Second
			}
			callCtx, cancelCall := context.WithTimeout(context.Background(), timeout)
			defer cancelCall()
			result := make(chan error, 1)
			go func() {
				if scenario == "blocked-write" {
					_, err := c.call(callCtx, managerPath, managerInterface+".SyntheticFixture", strings.Repeat("x", 4<<20))
					result <- err
					return
				}
				_, err := managerRequest(c, callCtx)
				result <- err
			}()
			<-seen
			start := time.Now()
			if scenario == "lifetime-cancel" {
				cancelLifetime()
			}
			if scenario == "concurrent-close" {
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() { _ = c.Close() })
				}
				wg.Wait()
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("interrupted call succeeded")
				}
				if (scenario == "call-deadline" || scenario == "blocked-write") && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("deadline lost", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("call or blocked write did not stop before peer closure")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("close did not join promptly")
			}
			if c.directory.files != nil {
				t.Fatal("closed manager retained namespace")
			}
		})
	}
}

func TestLinuxManagerAuthenticatesKernelUID(t *testing.T) {
	managerFixture(t)
	root, err := os.MkdirTemp("/unprivileged", "manager-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	// The caller requires protected ancestry. /unprivileged is intentionally
	// public for executing the child; place its socket instead below /fixture.
	socketDir := filepath.Join("/fixture", filepath.Base(root))
	if err := os.Mkdir(socketDir, 0777); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	// Give the child only an already-open directory, not access to /fixture.
	if err := os.Chmod(socketDir, 0777); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(socketDir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/unprivileged/linuxservice.test", "-test.run=^TestLinuxManagerUnprivilegedPeerHelper$", "-test.count=1")
	cmd.Env = []string{"OPENUEM_TEST_MANAGER_CHILD=owned-unprivileged-peer"}
	cmd.ExtraFiles = []*os.File{d}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			cancel()
			_ = cmd.Wait()
		}
	}()
	r := bufio.NewReader(stdout)
	line, err := r.ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("unprivileged listener failed: %q %v %s", line, err, stderr.String())
	}
	socketPath := filepath.Join(socketDir, "private")
	if err := os.Chown(socketPath, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketDir, 0700); err != nil {
		t.Fatal(err)
	}
	if c, err := connectPrivateManager(ctx, socketPath, int32(cmd.Process.Pid)); c != nil || !errors.Is(err, ErrManager) {
		if c != nil {
			c.Close()
		}
		t.Fatal("root-owned socket concealed foreign kernel UID", err)
	}
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	joined = true
	if err != nil || !bytes.Contains(output, []byte("no-auth-bytes\n")) {
		t.Fatalf("kernel credential rejection failed: %v %s %s", err, output, stderr.String())
	}
}

func TestLinuxManagerUnprivilegedPeerHelper(t *testing.T) {
	if os.Getenv("OPENUEM_TEST_MANAGER_CHILD") != "owned-unprivileged-peer" {
		t.Skip("requires owned unprivileged peer helper")
	}
	if os.Geteuid() != 65534 {
		t.Fatal("peer helper must run as the fixture UID")
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: "/proc/self/fd/3/private", Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	defer l.Close()
	fmt.Println("ready")
	wire, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer wire.Close()
	var first [1]byte
	n, err := wire.Read(first[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("foreign UID received auth bytes", n, err)
	}
	fmt.Println("no-auth-bytes")
}

func TestLinuxManagerJoinsTruncatedMessageAlignment(t *testing.T) {
	for _, scenario := range []string{"padding-close", "oversized-header", "overflow-header", "malformed-complete"} {
		t.Run(scenario, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			peer := newManagerPeer(t, managerFixture(t), func(wire *net.UnixConn) error {
				r, err := authenticateManagerPeer(wire, false)
				if err != nil {
					return err
				}
				call, err := dbus.DecodeMessage(r)
				if err != nil {
					return err
				}
				var encoded bytes.Buffer
				if err := sendManagerReply(&encoded, call, "", unitObjectPath); err != nil {
					return err
				}
				data := encoded.Bytes()
				fields := int(binary.LittleEndian.Uint32(data[12:16]))
				// Encode the two headers in a fixed order. Go map iteration can
				// otherwise put the serial last and produce no final padding.
				body := bytes.Clone(data[16+((fields+7)&^7):])
				data = append(bytes.Clone(data[:16]), 5, 1, 'u', 0, 0, 0, 0, 0, 8, 1, 'g', 0, 1, 'o', 0, 0)
				binary.LittleEndian.PutUint32(data[12:16], 15)
				binary.LittleEndian.PutUint32(data[20:24], call.Serial())
				data = append(data, body...)
				fields = 15
				if !validManagerFrame(data) {
					return errors.New("fixture alignment frame is not valid")
				}
				switch scenario {
				case "padding-close":
					data = data[:16+fields]
				case "oversized-header":
					binary.LittleEndian.PutUint32(data[12:16], maxManagerMessage)
				case "overflow-header":
					binary.LittleEndian.PutUint32(data[12:16], ^uint32(0))
					binary.LittleEndian.PutUint32(data[4:8], ^uint32(0))
				case "malformed-complete":
					data[1] = 0
				}
				if _, err := wire.Write(data); err != nil {
					return err
				}
				if scenario == "padding-close" {
					// The client has consumed the prefix and is waiting precisely
					// at the library's former unguarded alignment boundary.
					transport := managerTransport{UnixConn: wire, ctx: t.Context(), deadline: time.Now().Add(time.Second)}
					if err := transport.drainAuthentication(); err != nil {
						return err
					}
				}
				close(entered)
				<-release
				return nil
			})
			c, err := connectPrivateManager(t.Context(), peer.path, int32(os.Getpid()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			done := make(chan error, 1)
			go func() { _, err := managerRequest(c, t.Context()); done <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("peer did not send the held frame")
			}
			if scenario == "padding-close" {
				c.Close()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("incomplete or oversized frame was admitted")
				}
			case <-time.After(time.Second):
				t.Fatal("invalid frame did not release the pending call")
			}
		})
	}
}
