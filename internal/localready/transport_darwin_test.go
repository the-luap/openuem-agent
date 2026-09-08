package localready

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func shortDirectory(t *testing.T) string {
	t.Helper()
	path, err := os.MkdirTemp("/tmp", "uem-ready-")
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

func TestNativeReadinessTransitionsIdentityAndSingleton(t *testing.T) {
	key, public := fixtureKey(t)
	identity, directory, uid := fixtureIdentity(), shortDirectory(t), uint32(os.Geteuid())
	s, err := listen(context.Background(), directory, identity, key, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := probe(context.Background(), directory, identity, public, uid); !errors.Is(err, ErrNotReady) {
		t.Fatal("initialization was reported as ready", err)
	}
	if _, err := listen(context.Background(), directory, identity, key, uid); !errors.Is(err, ErrConflict) {
		t.Fatal("second server replaced the current endpoint", err)
	}
	if err := s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if err := probe(context.Background(), directory, identity, public, uid); err != nil {
		t.Fatal("native peer/identity proof failed", err)
	}
	other := identity
	other.SiteID++
	if err := probe(context.Background(), directory, other, public, uid); !errors.Is(err, ErrConflict) {
		t.Fatal("another protected scope was accepted", err)
	}
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: s.socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer(connection, uid+1); !errors.Is(err, ErrConflict) {
		t.Fatal("native peer UID mismatch accepted", err)
	}
	connection.Close()
	address, err := os.ReadFile(filepath.Join(directory, addressName))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := s.MarkReady(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed service became ready")
	}
	if _, err := os.Lstat(s.socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned socket survived joined shutdown", err)
	}
	second, err := listen(context.Background(), directory, identity, key, uid)
	if err != nil {
		t.Fatal("ordinary restart failed", err)
	}
	defer second.Close()
	after, err := os.ReadFile(filepath.Join(directory, addressName))
	if err != nil || !bytes.Equal(address, after) {
		t.Fatal("restart replaced immutable endpoint metadata", err)
	}
}

type heldSigner struct {
	nkeys.KeyPair
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (k *heldSigner) Sign(data []byte) ([]byte, error) {
	k.once.Do(func() { close(k.entered) })
	<-k.release
	return k.KeyPair.Sign(data)
}

func TestNativeReadinessShutdownJoinsSigningBeforeKeyRelease(t *testing.T) {
	key, _ := fixtureKey(t)
	held := &heldSigner{KeyPair: key, entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	defer release()
	directory := shortDirectory(t)
	s, err := listen(context.Background(), directory, fixtureIdentity(), held, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer release()
	connection, err := net.Dial("unix", s.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.Write(append([]byte(requestMagic), make([]byte, 32)...))
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("signer was not reached")
	}
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
		t.Fatal("shutdown released borrowed keys during signing")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not join its work")
	}
}

var crashDirectory = flag.String("openuem-readiness-crash-fixture", "", "Private directory for an isolated crash fixture")

func TestNativeReadinessCrashHelper(t *testing.T) {
	if *crashDirectory == "" {
		t.Skip("isolated subprocess only")
	}
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	s, err := listen(context.Background(), *crashDirectory, fixtureIdentity(), key, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	os.Exit(23) // Deliberately bypass all cleanup; the kernel releases flock.
}

func TestNativeReadinessRecoversAnActualCrashedSocketWithoutReplacingForeignFiles(t *testing.T) {
	directory := shortDirectory(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, executable, "-test.run=^TestNativeReadinessCrashHelper$", "-openuem-readiness-crash-fixture="+directory).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatal("crash fixture failed before opening the socket", err, string(output))
	}
	key, public := fixtureKey(t)
	identity, uid := fixtureIdentity(), uint32(os.Geteuid())
	s, err := listen(context.Background(), directory, identity, key, uid)
	if err != nil {
		t.Fatal("stale owned socket prevented recovery", err)
	}
	defer s.Close()
	if err := s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if err := probe(context.Background(), directory, identity, public, uid); err != nil {
		t.Fatal(err)
	}
	s.Close()
	foreign := []byte("preserve this unrelated file")
	if err := os.WriteFile(s.socketPath, foreign, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(context.Background(), directory, identity, key, uid); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign endpoint file was adopted", err)
	}
	after, err := os.ReadFile(s.socketPath)
	if err != nil || !bytes.Equal(after, foreign) {
		t.Fatal("foreign file was replaced", err)
	}
}

func TestNativeReadinessRejectsUnsafeDirectoriesAndPreservesReplacements(t *testing.T) {
	key, _ := fixtureKey(t)
	identity, uid := fixtureIdentity(), uint32(os.Geteuid())
	directory := shortDirectory(t)
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(context.Background(), directory, identity, key, uid); !errors.Is(err, ErrUnavailable) {
		t.Fatal("shared identity directory accepted", err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := listen(context.Background(), directory, identity, key, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := os.Rename(s.socketPath, s.socketPath+".old"); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("replacement must survive cleanup")
	if err := os.WriteFile(s.socketPath, foreign, 0600); err != nil {
		t.Fatal(err)
	}
	s.Close()
	after, err := os.ReadFile(s.socketPath)
	if err != nil || !bytes.Equal(after, foreign) {
		t.Fatal("cleanup removed a replacement", err)
	}
}

func TestNativeReadinessPublicEntryRequiresRoot(t *testing.T) {
	key, public := fixtureKey(t)
	directory, identity := shortDirectory(t), fixtureIdentity()
	s, err := Listen(context.Background(), directory, identity, key)
	if os.Geteuid() != 0 {
		if !errors.Is(err, ErrUnavailable) || s != nil {
			t.Fatal("non-root readiness server admitted", err)
		}
		if err := Probe(context.Background(), directory, identity, public); !errors.Is(err, ErrUnavailable) {
			t.Fatal("non-root probe admitted", err)
		}
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			t.Fatal("rejected non-root request created state", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if err := Probe(context.Background(), directory, identity, public); err != nil {
		t.Fatal("root entry point failed", err)
	}
}

func TestNativeReadinessCancellationClosesIdleClients(t *testing.T) {
	key, _ := fixtureKey(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := listen(ctx, shortDirectory(t), fixtureIdentity(), key, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var connections []net.Conn
	defer func() {
		for _, connection := range connections {
			connection.Close()
		}
	}()
	for range 8 {
		connection, err := net.Dial("unix", s.socketPath)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
		if _, err := connection.Write([]byte(requestMagic[:1])); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle client prevented joined cancellation")
	}
	for _, connection := range connections {
		connection.SetReadDeadline(time.Now().Add(time.Second))
		var data [1]byte
		if _, err := connection.Read(data[:]); err == nil {
			t.Fatal("canceled endpoint remained usable")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("cancellation left a client open")
		}
	}
}

func TestNativeReadinessProbeRejectsSocketAliasesAndHonorsCancellation(t *testing.T) {
	key, public := fixtureKey(t)
	directory, identity, uid := shortDirectory(t), fixtureIdentity(), uint32(os.Geteuid())
	s, err := listen(context.Background(), directory, identity, key, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(s.socketPath, s.socketPath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(s.socketPath+".old", s.socketPath); err != nil {
		t.Fatal(err)
	}
	if err := probe(context.Background(), directory, identity, public, uid); !errors.Is(err, ErrConflict) {
		t.Fatal("socket alias accepted", err)
	}
	if err := os.Remove(s.socketPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(s.socketPath+".old", s.socketPath); err != nil {
		t.Fatal(err)
	}
	s.Close()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := probe(ctx, directory, identity, public, uid); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("stalled endpoint ignored cancellation", err)
	}
	if _, err := listen(context.Background(), directory, identity, key, uid); !errors.Is(err, ErrConflict) {
		t.Fatal("active foreign endpoint was replaced", err)
	}
}
