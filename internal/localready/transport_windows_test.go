package localready

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/windows"
)

func privateReadinessDirectory(t *testing.T) string {
	t.Helper()
	if !windowsPrivilegedToken(windows.GetCurrentProcessToken(), false) {
		t.Skip("native private readiness fixtures require an elevated test runner")
	}
	path := filepath.Join(t.TempDir(), "identity")
	name, _ := windows.UTF16PtrFromString(path)
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(name, &attributes)
	runtime.KeepAlive(sd)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNativeWindowsReadinessBindsIdentityPIDAndSingleton(t *testing.T) {
	directory := privateReadinessDirectory(t)
	identity := fixtureIdentity()
	key, public := fixtureKey(t)
	s, err := listenWindows(t.Context(), directory, identity, key, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	probe := func(i Identity, public string, pid uint32) error {
		return probeWindows(t.Context(), directory, i, public, pid, true)
	}
	if err = probe(identity, public, uint32(os.Getpid())); !errors.Is(err, ErrNotReady) {
		t.Fatal("listener admitted readiness before initialization", err)
	}
	if _, err = listenWindows(t.Context(), directory, identity, key, true); !errors.Is(err, ErrConflict) {
		t.Fatal("second listener replaced the endpoint", err)
	}
	if err = s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if err = probe(identity, public, uint32(os.Getpid())); err != nil {
		t.Fatal("native identity/PID proof failed", err)
	}
	other := identity
	other.SiteID++
	if err = probe(other, public, uint32(os.Getpid())); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign scope accepted", err)
	}
	_, foreign := fixtureKey(t)
	if err = probe(identity, foreign, uint32(os.Getpid())); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign broker key accepted", err)
	}
	if err = probe(identity, public, uint32(os.Getpid()+1)); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign process accepted", err)
	}
	if !windowsPrivilegedToken(windows.GetCurrentProcessToken(), true) {
		if _, err = Listen(t.Context(), directory, identity, key); !errors.Is(err, ErrUnavailable) {
			t.Fatal("public listener accepted a non-System process", err)
		}
		if err = ProbeProcess(t.Context(), directory, identity, public, uint32(os.Getpid())); !errors.Is(err, ErrConflict) {
			t.Fatal("public probe accepted a non-System server", err)
		}
	}
	before, err := os.ReadFile(filepath.Join(directory, pipeAddressFile))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkReady(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed service became ready")
	}
	second, err := listenWindows(t.Context(), directory, identity, key, true)
	if err != nil {
		t.Fatal("restart failed", err)
	}
	defer second.Close()
	after, err := os.ReadFile(filepath.Join(directory, pipeAddressFile))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("restart changed protected address", err)
	}
}

type windowsHeldSigner struct {
	nkeys.KeyPair
	entered, release chan struct{}
	once             sync.Once
}

func (s *windowsHeldSigner) Sign(data []byte) ([]byte, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.KeyPair.Sign(data)
}

func TestNativeWindowsReadinessShutdownJoinsBorrowedSignerAndIdleClients(t *testing.T) {
	directory := privateReadinessDirectory(t)
	key, _ := fixtureKey(t)
	held := &windowsHeldSigner{KeyPair: key, entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	s, err := listenWindows(t.Context(), directory, fixtureIdentity(), held, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer release()
	name, address, err := windowsPipeAddress(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	address.Close()
	connection, err := winio.DialPipeAccess(t.Context(), name, pipeClientAccess)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = connection.Write(append([]byte(requestMagic), make([]byte, 32)...)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("signer not reached")
	}
	idle, err := winio.DialPipeAccess(t.Context(), name, pipeClientAccess)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
		t.Fatal("closed borrowed signer before joining")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle client prevented joined shutdown")
	}
}

func TestNativeWindowsReadinessRejectsChangedPermissionsAndPartialAddress(t *testing.T) {
	for _, mode := range []string{"partial-address", "public-directory", "address-write"} {
		t.Run(mode, func(t *testing.T) {
			directory := privateReadinessDirectory(t)
			key, public := fixtureKey(t)
			identity := fixtureIdentity()
			if mode == "partial-address" {
				_, address, err := windowsPipeAddress(directory, true)
				if err != nil {
					t.Fatal(err)
				}
				address.Close()
				if err := os.WriteFile(filepath.Join(directory, pipeAddressFile), []byte("unfinished"), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := listenWindows(t.Context(), directory, identity, key, true); err == nil {
					t.Fatal("partial address was replaced or trusted")
				}
				data, err := os.ReadFile(filepath.Join(directory, pipeAddressFile))
				if err != nil || string(data) != "unfinished" {
					t.Fatal("partial address was removed", err)
				}
				return
			}
			s, err := listenWindows(t.Context(), directory, identity, key, true)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if mode == "address-write" {
				if err = os.WriteFile(filepath.Join(directory, pipeAddressFile), []byte("replacement"), 0600); err == nil {
					t.Fatal("immutable address admitted a competing writer")
				}
				return
			}
			sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FR;;;WD)")
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
			err = windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
			runtime.KeepAlive(sd)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.MarkReady(); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unsafe directory became ready", err)
			}
			if err = probeWindows(t.Context(), directory, identity, public, uint32(os.Getpid()), true); err == nil {
				t.Fatal("unsafe directory accepted a readiness proof")
			}
		})
	}
}

var windowsReadinessCrashDirectory = flag.String("openuem-readiness-windows-crash-fixture", "", "Owned private directory for an isolated named-pipe crash fixture")

func TestNativeWindowsReadinessCrashHelper(t *testing.T) {
	if *windowsReadinessCrashDirectory == "" {
		t.Skip("isolated subprocess only")
	}
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	s, err := listenWindows(t.Context(), *windowsReadinessCrashDirectory, fixtureIdentity(), key, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.MarkReady(); err != nil {
		t.Fatal(err)
	}
	os.Exit(23)
}

func TestNativeWindowsReadinessRecoversAfterProcessExit(t *testing.T) {
	directory := privateReadinessDirectory(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeWindowsReadinessCrashHelper$", "-openuem-readiness-windows-crash-fixture="+directory)
	err := command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatal("crash fixture failed", err)
	}
	before, err := os.ReadFile(filepath.Join(directory, pipeAddressFile))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := fixtureKey(t)
	s, err := listenWindows(t.Context(), directory, fixtureIdentity(), key, true)
	if err != nil {
		t.Fatal("crashed pipe prevented restart", err)
	}
	defer s.Close()
	after, err := os.ReadFile(filepath.Join(directory, pipeAddressFile))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("crash recovery replaced identity address", err)
	}
}
