package enrollmentstore

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func windowsFixture(t *testing.T) (NativeBackend, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "identity")
	b, err := OpenNative(directory)
	if err != nil {
		t.Fatal("could not create system-protected storage; native tests require an elevated Windows runner", err)
	}
	t.Cleanup(func() { b.Close() })
	return b, directory
}

func TestWindowsDPAPIDurableEnrollmentRecovery(t *testing.T) {
	b, _ := windowsFixture(t)
	runDurableEnrollmentRecovery(t, b)
}

func TestWindowsStateIsEncryptedPrivateImmutableAndRecoverable(t *testing.T) {
	b, directory := windowsFixture(t)
	plaintext := []byte("isolated private identity fixture, never a production key")
	if _, err := b.Load(pendingRecord); !errors.Is(err, ErrMissing) {
		t.Fatal("fresh backend returned a record", err)
	}
	if err := b.Create(pendingRecord, plaintext); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, pendingRecord+".dpapi")
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, plaintext) || len(ciphertext) == 0 {
		t.Fatal("plaintext was written to the state file")
	}
	if err = b.Create(pendingRecord, []byte("replacement")); !errors.Is(err, ErrExists) {
		t.Fatal("existing state could be replaced", err)
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Load(pendingRecord); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed backend returned private state", err)
	}
	restarted, err := OpenNative(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	loaded, err := restarted.Load(pendingRecord)
	if err != nil || !bytes.Equal(loaded, plaintext) {
		t.Fatal("restart did not recover encrypted state", err)
	}
	clear(loaded)
	// Copying a valid encrypted record to another stage must not change its
	// meaning: DPAPI entropy binds pending and identity records separately.
	file, err := createSystemFile(filepath.Join(directory, identityRecord+".dpapi"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(ciphertext); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	if _, err = restarted.Load(identityRecord); !errors.Is(err, ErrUnavailable) {
		t.Fatal("a copied record changed its protected purpose", err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	if err = os.WriteFile(path, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Load(pendingRecord); !errors.Is(err, ErrUnavailable) {
		t.Fatal("tampered protected state was accepted", err)
	}
	for _, name := range []string{"", "../escape", "pending/../identity", "PENDING"} {
		if err = restarted.Create(name, plaintext); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid record name accepted", err)
		}
	}
	for _, data := range [][]byte{nil, make([]byte, maxRecordSize+1)} {
		if err = restarted.Create(pendingRecord, data); !errors.Is(err, ErrUnavailable) {
			t.Fatal("unbounded record accepted", err)
		}
	}
	files, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatal("failed publication left temporary credential files")
	}
}

func TestWindowsConcurrentPublishHasOneCompleteWinner(t *testing.T) {
	b, _ := windowsFixture(t)
	results := make(chan error, 12)
	var jobs sync.WaitGroup
	for i := 0; i < 12; i++ {
		jobs.Go(func() { results <- b.Create(pendingRecord, bytes.Repeat([]byte{byte(i + 1)}, 8192)) })
	}
	jobs.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrExists) {
			t.Fatal("concurrent publication failed outside the exclusive-create contract", err)
		}
	}
	if winners != 1 {
		t.Fatal("publication had more than one winner", winners)
	}
	data, err := b.Load(pendingRecord)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if len(data) != 8192 || data[0] < 1 || data[0] > 12 || !bytes.Equal(data, bytes.Repeat(data[:1], len(data))) {
		t.Fatal("published record was incomplete or mixed between writers")
	}
}

func setWindowsAccess(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(sd)
}

func TestWindowsStateRejectsSharedDirectoriesAndSharedCiphertext(t *testing.T) {
	b, directory := windowsFixture(t)
	if err := b.Create(pendingRecord, []byte("private access fixture")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, pendingRecord+".dpapi")
	private := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	setWindowsAccess(t, path, private+"(A;;GR;;;WD)")
	if _, err := b.Load(pendingRecord); !errors.Is(err, ErrUnavailable) {
		t.Fatal("Everyone-readable machine-DPAPI state was accepted", err)
	}
	setWindowsAccess(t, path, private)
	setWindowsAccess(t, directory, private+"(A;;FA;;;WD)")
	if _, err := OpenNative(directory); !errors.Is(err, ErrUnavailable) {
		t.Fatal("shared credential directory was accepted", err)
	}
	if err := b.Create(identityRecord, []byte("must not be published")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("open backend ignored weakened directory access", err)
	}
	if err := checkSystemDirectory(directory); !errors.Is(err, ErrUnavailable) {
		t.Fatal("opening storage silently changed an existing directory ACL", err)
	}
	setWindowsAccess(t, directory, private)
}

var systemFixtureDirectory = flag.String("openuem-system-fixture-directory", "", "Private directory for the isolated service-account test")
var systemFixtureService = flag.String("openuem-system-fixture-service", "", "Unique service name for the isolated service-account test")

type systemFixtureHandler struct{ directory string }

func (h systemFixtureHandler) Execute(_ []string, _ <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.Running}
	b, err := OpenNative(h.directory)
	if err != nil {
		return true, 1
	}
	defer b.Close()
	data, err := b.Load(pendingRecord)
	if err != nil {
		return true, 2
	}
	defer clear(data)
	if string(data) != "isolated service-account fixture" {
		return true, 3
	}
	if err = b.Create(identityRecord, []byte("local-system-access-verified")); err != nil {
		return true, 4
	}
	return false, 0
}

func TestWindowsSystemServiceFixture(t *testing.T) {
	if *systemFixtureDirectory == "" || *systemFixtureService == "" {
		t.Skip("only the isolated service-account test launches this helper")
	}
	service, err := svc.IsWindowsService()
	if err != nil || !service {
		t.Fatal("helper is not running as a Windows service", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatal("helper is not running as Local System", err)
	}
	if err = svc.Run(*systemFixtureService, systemFixtureHandler{*systemFixtureDirectory}); err != nil {
		t.Fatal(err)
	}
}

func TestElevatedInstallerAndLocalSystemServiceShareTheProtectedState(t *testing.T) {
	b, directory := windowsFixture(t)
	if err := b.Create(pendingRecord, []byte("isolated service-account fixture")); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal("native service-account test requires service-manager access", err)
	}
	defer manager.Disconnect()
	name := "OpenUEMIdentityFixture-" + uuid.NewString()
	service, err := manager.CreateService(name, executable, mgr.Config{StartType: mgr.StartManual, DisplayName: name}, "-test.run=^TestWindowsSystemServiceFixture$", "-openuem-system-fixture-directory="+directory, "-openuem-system-fixture-service="+name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		service.Control(svc.Stop)
		if err := service.Delete(); err != nil {
			t.Error("could not remove isolated test service", err)
		}
		service.Close()
	}()
	if err = service.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := b.Load(identityRecord)
		if err == nil {
			defer clear(data)
			if string(data) != "local-system-access-verified" {
				t.Fatal("service returned an unexpected state")
			}
			return
		}
		if !errors.Is(err, ErrMissing) {
			t.Fatal("could not read the service-published identity", err)
		}
		state, err := service.Query()
		if err != nil {
			t.Fatal(err)
		}
		if state.State == svc.Stopped {
			t.Fatal("Local System helper stopped before publishing its result", state.Win32ExitCode, state.ServiceSpecificExitCode)
		}
		select {
		case <-deadline.C:
			t.Fatal("Local System did not recover/publish protected state")
		case <-ticker.C:
		}
	}
}
