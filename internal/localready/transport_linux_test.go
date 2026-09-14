package localready

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

func linuxReadyFixture(t *testing.T) string {
	t.Helper()
	if os.Getenv("OPENUEM_TEST_LINUX_READINESS") != "owned-isolated-readiness" {
		t.Skip("requires isolated root Linux readiness fixture")
	}
	var fs unix.Statfs_t
	if os.Geteuid() != 0 || unix.Statfs("/fixture", &fs) != nil || fs.Type != unix.TMPFS_MAGIC || os.TempDir() != "/fixture" {
		t.Fatal("native readiness requires owned private tmpfs")
	}
	path, err := os.MkdirTemp("/fixture", "ready-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	return path
}

func TestLinuxReadinessTransitionsIdentityAndSingleton(t *testing.T) {
	path := linuxReadyFixture(t)
	key, public := fixtureKey(t)
	identity := fixtureIdentity()
	s, err := Listen(context.Background(), path, identity, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = Probe(context.Background(), path, identity, public); !errors.Is(err, ErrNotReady) {
		t.Fatal("initializing endpoint was ready", err)
	}
	if _, err = Listen(context.Background(), path, identity, key); !errors.Is(err, ErrConflict) {
		t.Fatal("second listener displaced its owner", err)
	}
	if err = s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if err = Probe(context.Background(), path, identity, public); err != nil {
		t.Fatal("native root peer and signed identity did not verify", err)
	}
	other := identity
	other.SiteID++
	if err = Probe(context.Background(), path, other, public); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign identity accepted", err)
	}
	_, otherPublic := fixtureKey(t)
	if err = Probe(context.Background(), path, identity, otherPublic); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign signing key accepted", err)
	}
	address, err := os.ReadFile(filepath.Join(path, addressName))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkReady(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed endpoint became ready", err)
	}
	if _, err = os.Lstat(filepath.Join(path, s.address)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned socket survived joined close", err)
	}
	second, err := Listen(context.Background(), path, identity, key)
	if err != nil {
		t.Fatal("restart rejected retained address", err)
	}
	defer second.Close()
	after, err := os.ReadFile(filepath.Join(path, addressName))
	if err != nil || !bytes.Equal(address, after) {
		t.Fatal("restart changed immutable address metadata", err)
	}
}

func TestLinuxReadinessRejectsUnsafeOrChangedNamespace(t *testing.T) {
	for _, mutation := range []string{"root-mode", "parent-mode", "root-owner", "ancestor-symlink", "root-inode", "lock-hardlink", "address-hardlink", "socket-inode"} {
		t.Run(mutation, func(t *testing.T) {
			parent := linuxReadyFixture(t)
			path := filepath.Join(parent, "id")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			key, public := fixtureKey(t)
			identity := fixtureIdentity()
			s, err := Listen(context.Background(), path, identity, key)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			preserved := filepath.Join(path, s.address)
			switch mutation {
			case "root-mode":
				err = os.Chmod(path, 0755)
			case "parent-mode":
				err = os.Chmod(parent, 0777)
			case "root-owner":
				err = os.Chown(path, 65534, 65534)
			case "ancestor-symlink":
				if err = os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(path+".old", path)
			case "root-inode":
				if err = os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				err = os.Mkdir(path, 0700)
				preserved = filepath.Join(path+".old", s.address)
			case "lock-hardlink":
				err = os.Link(filepath.Join(path, lockName), filepath.Join(path, "lock-copy"))
			case "address-hardlink":
				err = os.Link(filepath.Join(path, addressName), filepath.Join(path, "address-copy"))
			case "socket-inode":
				if err = os.Rename(preserved, preserved+".old"); err != nil {
					t.Fatal(err)
				}
				err = os.WriteFile(preserved, []byte("unrelated preserved data"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = s.MarkReady(); !errors.Is(err, ErrUnavailable) {
				t.Fatal("changed native endpoint became ready", err)
			}
			if err = Probe(context.Background(), path, identity, public); err == nil {
				t.Fatal("changed native endpoint verified")
			}
			closeErr := s.Close()
			if mutation != "lock-hardlink" && mutation != "address-hardlink" {
				if closeErr == nil {
					t.Fatal("ambiguous namespace was cleaned as an owned endpoint")
				}
				if _, err = os.Lstat(preserved); err != nil {
					t.Fatal("cleanup erased unrelated or ambiguous data", err)
				}
			}
		})
	}
}

type linuxHeldSigner struct {
	nkeys.KeyPair
	entered, release chan struct{}
	once             sync.Once
}

func (k *linuxHeldSigner) Sign(data []byte) ([]byte, error) {
	k.once.Do(func() { close(k.entered) })
	<-k.release
	return k.KeyPair.Sign(data)
}

func TestLinuxReadinessShutdownJoinsSigningAndDisconnectedClients(t *testing.T) {
	path := linuxReadyFixture(t)
	key, _ := fixtureKey(t)
	held := &linuxHeldSigner{KeyPair: key, entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	defer release()
	s, err := Listen(context.Background(), path, fixtureIdentity(), held)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer release()
	connection, err := net.Dial("unix", filepath.Join(path, s.address))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.Write(append([]byte(requestMagic), make([]byte, 32)...)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native signing did not start")
	}
	connection.Close()
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case <-done:
		t.Fatal("close released keys before signing joined")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not join native signer")
	}
	for round := 0; round < 12; round++ {
		s, err := Listen(context.Background(), path, fixtureIdentity(), key)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 4; i++ {
			c, e := net.Dial("unix", filepath.Join(path, s.address))
			if e != nil {
				t.Fatal(e)
			}
			c.Close()
		}
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _ = s.MarkReady(); _ = s.Close() }()
		}
		wg.Wait()
	}
}

func TestLinuxReadinessRechecksAuthorityAfterSigning(t *testing.T) {
	path := linuxReadyFixture(t)
	key, public := fixtureKey(t)
	held := &linuxHeldSigner{KeyPair: key, entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	defer release()
	identity := fixtureIdentity()
	s, err := Listen(context.Background(), path, identity, held)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer release()
	if err = s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Probe(context.Background(), path, identity, public) }()
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("signing not reached")
	}
	if err = os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	release()
	if err = <-done; err == nil {
		t.Fatal("readiness survived an authority change during signing")
	}
	if err = os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxReadinessReclaimsOnlyInactiveOwnedSocket(t *testing.T) {
	path := linuxReadyFixture(t)
	key, public := fixtureKey(t)
	identity := fixtureIdentity()
	directory, err := openLinuxReadyDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	address, err := directory.address(true)
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(path, address)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(socketPath, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Listen(context.Background(), path, identity, key); !errors.Is(err, ErrConflict) {
		t.Fatal("active foreign listener was displaced", err)
	}
	listener.Close()
	s, err := Listen(context.Background(), path, identity, key)
	if err != nil {
		t.Fatal("inactive exact owned socket was not reclaimed", err)
	}
	defer s.Close()
	if err = s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if err = Probe(context.Background(), path, identity, public); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxReadinessRejectsForeignPIDAndBoundsProbe(t *testing.T) {
	for _, scenario := range []string{"wrong-pid", "silent", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			path := linuxReadyFixture(t)
			key, public := fixtureKey(t)
			identity := fixtureIdentity()
			directory, err := openLinuxReadyDirectory(path)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.close()
			address, err := directory.address(true)
			if err != nil {
				t.Fatal(err)
			}
			socketPath := filepath.Join(path, address)
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err = os.Chmod(socketPath, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := listener.AcceptUnix()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(4 * time.Second))
				if scenario == "wrong-pid" {
					_ = reply(c, identity, key, os.Getpid()+1, true)
				} else {
					if scenario == "cancel" {
						cancel()
					}
					_, _ = io.Copy(io.Discard, c)
				}
			}()
			started := time.Now()
			err = Probe(ctx, path, identity, public)
			<-done
			want := ErrConflict
			if scenario == "silent" {
				want = context.DeadlineExceeded
			}
			if scenario == "cancel" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || time.Since(started) > 3*time.Second {
				t.Fatal("native PID/cancellation/probe deadline not enforced", err)
			}
		})
	}
}

func TestLinuxReadinessUnprivilegedPeerHelper(t *testing.T) {
	path := os.Getenv("OPENUEM_TEST_READINESS_PEER")
	if path == "" {
		t.Skip("owned unprivileged child only")
	}
	if os.Geteuid() != 65534 || !strings.HasPrefix(path, "/unprivileged/ready-") {
		t.Fatal("unsafe child fixture")
	}
	if _, err := Listen(context.Background(), "/fixture", fixtureIdentity(), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unprivileged listener admitted")
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || err == nil {
		t.Fatal("unprivileged peer received readiness data")
	}
}

func TestLinuxReadinessAuthenticatesKernelRootPeer(t *testing.T) {
	linuxReadyFixture(t)
	var fs unix.Statfs_t
	if unix.Statfs("/unprivileged", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Fatal("missing owned public helper mount")
	}
	path := "/unprivileged/ready-" + uuid.NewString() + ".sock"
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/unprivileged/readiness.test", "-test.run=^TestLinuxReadinessUnprivilegedPeerHelper$", "-test.timeout=4s")
	cmd.Env = append(os.Environ(), "OPENUEM_TEST_READINESS_PEER="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
	c, acceptErr := listener.AcceptUnix()
	var peerErr error
	if acceptErr == nil {
		_, peerErr = linuxReadyPeer(c)
		c.Close()
	}
	waitErr := cmd.Wait()
	if acceptErr != nil || !errors.Is(peerErr, ErrConflict) || waitErr != nil {
		t.Fatalf("kernel root peer boundary failed: accept=%v peer=%v child=%v %s", acceptErr, peerErr, waitErr, output.String())
	}
}
