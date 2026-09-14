package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"golang.org/x/sys/unix"
)

func linuxBackendFixture(t *testing.T) (*linuxBackend, string) {
	t.Helper()
	cipher := linuxCipherFixture(t)
	if err := cipher.Close(); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(linuxServiceLeaseDirectory(t), "identity")
	backend, err := OpenNative(directory)
	if err != nil {
		t.Fatal(err)
	}
	b := backend.(*linuxBackend)
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	return b, directory
}
func linuxStoredRecord(directory, record string) string {
	return filepath.Join(directory, linuxRecordDirectory, record+linuxRecordSuffix)
}

func TestLinuxEncryptedBackendRequiresProvisionedKeyBeforeCreatingState(t *testing.T) {
	b, directory := linuxBackendFixture(t)
	if err := b.Create(pendingRecord, []byte("owned retained identity")); err != nil {
		t.Fatal(err)
	}
	path := linuxStoredRecord(directory, pendingRecord)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key := "/var/lib/systemd/credential.secret"
	if err := os.Rename(key, key+".owned-retained"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Rename(key+".owned-retained", key); err != nil {
			t.Error(err)
		}
	}()
	fresh := filepath.Join(filepath.Dir(directory), "fresh")
	if other, err := OpenNative(fresh); other != nil || !errors.Is(err, ErrUnavailable) {
		if other != nil {
			other.Close()
		}
		t.Fatal("missing OS key did not prevent opening storage", err)
	}
	for _, absent := range []string{fresh, key} {
		if _, err := os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("missing prerequisite caused provisioning", err)
		}
	}
	if got, err := b.Load(pendingRecord); got != nil || !errors.Is(err, ErrUnavailable) {
		clear(got)
		t.Fatal("detached key retained read authority", err)
	}
	if err := b.Create(identityRecord, []byte("replacement")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("detached key retained publication authority", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("missing key changed retained ciphertext", err)
	}
}

func TestLinuxEncryptedBackendRefusesUnsafeInitialDirectoriesWithoutRepair(t *testing.T) {
	linuxCipherFixture(t)
	for _, kind := range []string{"missing parent", "shared parent", "symlink installation", "shared installation", "foreign installation", "shared credentials"} {
		t.Run(kind, func(t *testing.T) {
			base := linuxServiceLeaseDirectory(t)
			path := filepath.Join(base, "identity")
			var err error
			switch kind {
			case "missing parent":
				path = filepath.Join(base, "absent", "identity")
			case "shared parent":
				err = os.Chmod(base, 0777)
			case "symlink installation":
				err = os.Symlink(base, path)
			default:
				err = os.Mkdir(path, 0700)
				if err == nil {
					switch kind {
					case "shared installation":
						err = os.Chmod(path, 0755)
					case "foreign installation":
						err = os.Chown(path, 65534, 65534)
					case "shared credentials":
						err = os.Mkdir(filepath.Join(path, linuxRecordDirectory), 0755)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before, beforeErr := os.Lstat(path)
			if b, err := OpenNative(path); b != nil || !errors.Is(err, ErrUnavailable) {
				if b != nil {
					b.Close()
				}
				t.Fatal("unsafe initial namespace was accepted", err)
			}
			after, afterErr := os.Lstat(path)
			if errors.Is(beforeErr, os.ErrNotExist) {
				if !errors.Is(afterErr, os.ErrNotExist) {
					t.Fatal("rejection created an installation", afterErr)
				}
			} else if beforeErr != nil || afterErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Sys().(*syscall.Stat_t).Uid != after.Sys().(*syscall.Stat_t).Uid {
				t.Fatal("rejection repaired or replaced existing state", beforeErr, afterErr)
			}
		})
	}
}

func TestLinuxEncryptedBackendRejectsUnprivilegedCreation(t *testing.T) {
	if directory := os.Getenv("OPENUEM_TEST_LINUX_BACKEND_UNPRIVILEGED"); directory != "" {
		if os.Geteuid() == 0 {
			t.Fatal("unprivileged child retained root")
		}
		if b, err := OpenNative(directory); b != nil || !errors.Is(err, ErrUnavailable) {
			if b != nil {
				b.Close()
			}
			t.Fatal("unprivileged process opened identity storage", err)
		}
		return
	}
	linuxCipherFixture(t)
	directory := filepath.Join(linuxServiceLeaseDirectory(t), "identity")
	// The owned fixture ancestry is private. Pass only the already opened test
	// executable so the child can run without widening any directory permissions.
	binary, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	cmd := exec.CommandContext(t.Context(), "/proc/self/fd/3", "-test.run=^TestLinuxEncryptedBackendRejectsUnprivilegedCreation$")
	cmd.ExtraFiles = []*os.File{binary}
	cmd.Env = append(os.Environ(), "OPENUEM_TEST_LINUX_BACKEND_UNPRIVILEGED="+directory)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged rejection failed: %v\n%s", err, output)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unprivileged rejection created state", err)
	}
}

func TestLinuxEncryptedBackendFailedWritePreservesCommittedIdentity(t *testing.T) {
	if directory := os.Getenv("OPENUEM_TEST_LINUX_BACKEND_FAILED_WRITE"); directory != "" {
		linuxCipherFixture(t)
		b, err := OpenNative(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		var original unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &original); err != nil {
			t.Fatal(err)
		}
		defer unix.Setrlimit(unix.RLIMIT_FSIZE, &original)
		signal.Ignore(syscall.SIGXFSZ)
		limited := original
		limited.Cur = 1
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &limited); err != nil {
			t.Fatal(err)
		}
		if err := b.Create(identityRecord, []byte("owned child identity")); !errors.Is(err, ErrUnavailable) {
			t.Fatal("partial encrypted write was published", err)
		}
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &original); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(filepath.Join(directory, linuxRecordDirectory))
		if err != nil || len(entries) != 1 || entries[0].Name() != pendingRecord+linuxRecordSuffix {
			t.Fatal("failed write changed committed state or leaked its temporary", err)
		}
		if err := b.Create(identityRecord, []byte("owned child identity")); err != nil {
			t.Fatal("explicit retry could not publish after restored storage", err)
		}
		return
	}
	b, directory := linuxBackendFixture(t)
	if err := b.Create(pendingRecord, []byte("owned retained keys")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(linuxStoredRecord(directory, pendingRecord))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestLinuxEncryptedBackendFailedWritePreservesCommittedIdentity$")
	cmd.Env = append(os.Environ(), "OPENUEM_TEST_LINUX_BACKEND_FAILED_WRITE="+directory)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native failed-write recovery failed: %v\n%s", err, output)
	}
	after, err := os.ReadFile(linuxStoredRecord(directory, pendingRecord))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed write replaced existing encrypted keys", err)
	}
	got, err := b.Load(identityRecord)
	defer clear(got)
	if err != nil || string(got) != "owned child identity" {
		t.Fatal("failed-write retry did not retain exact identity", err)
	}
}

func TestLinuxEncryptedBackendRetainsNativeStateMachineContracts(t *testing.T) {
	for _, kind := range []string{"enrollment recovery", "recipient", "rotation", "software", "software reconciliation", "renewal", "renewal confirmed resolution", "renewal cancelled resolution"} {
		t.Run(kind, func(t *testing.T) {
			b, _ := linuxBackendFixture(t)
			switch kind {
			case "enrollment recovery":
				runDurableEnrollmentRecovery(t, b)
			case "recipient":
				runDurableRecipient(t, b)
			case "rotation":
				runDurableRotationJournal(t, b)
			case "software":
				runDurableSoftwareJournal(t, b)
			case "software reconciliation":
				runDurableSoftwareReconciliation(t, b)
			case "renewal":
				runDurableIdentityRenewal(t, b)
			case "renewal confirmed resolution":
				runDurableIdentityRenewalResolution(t, b, true)
			case "renewal cancelled resolution":
				runDurableIdentityRenewalResolution(t, b, false)
			}
		})
	}
}

func TestLinuxEncryptedBackendRecoversLinuxEnrollmentAndRenewalOverNativeHTTPS(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		for _, workflow := range []string{"signed enrollment", "renewal handoff"} {
			t.Run(architecture+"/"+workflow, func(t *testing.T) {
				backend, directory := linuxBackendFixture(t)
				if workflow == "signed enrollment" {
					bootstrap := testBootstrap()
					bootstrap.Platform, bootstrap.Architecture = "linux", architecture
					runTargetDurableEnrollmentRecovery(t, backend, bootstrap)
				} else {
					runTargetDurableIdentityRenewal(t, backend, "linux", architecture)
				}
				if err := backend.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := Open(directory)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				identity, err := reopened.Load()
				if err != nil || identity.Platform != "linux" || identity.Architecture != architecture || identity.Response.TenantID != 3 || identity.Response.SiteID != 4 {
					if identity != nil {
						identity.Close()
					}
					t.Fatal("native restart lost the Linux target or scope", err)
				}
				identity.Close()
				if checkpoint, err := reopened.Checkpoint(); err != nil || checkpoint.Sequence != 42 || checkpoint.Digest == "" {
					t.Fatal("native restart lost its release checkpoint", err)
				}
			})
		}
	}
}

func TestLinuxEncryptedBackendPublishesPrivateImmutableBoundedRecords(t *testing.T) {
	b, directory := linuxBackendFixture(t)
	for _, record := range []string{pendingRecord, identityRecord, recipientRecord} {
		data := []byte("owned private identity bytes for " + record)
		if record == recipientRecord {
			data = bytes.Repeat([]byte{'x'}, maxRecordSize)
		}
		if _, err := b.Load(record); !errors.Is(err, ErrMissing) {
			t.Fatal(err)
		}
		if err := b.Create(record, data); err != nil {
			t.Fatal(err)
		}
		sealed, err := os.ReadFile(linuxStoredRecord(directory, record))
		if err != nil || len(sealed) == 0 || bytes.Contains(sealed, data) {
			t.Fatal("record was not encrypted", err)
		}
		stat, err := os.Lstat(linuxStoredRecord(directory, record))
		if err != nil || stat.Mode().Perm() != 0600 {
			t.Fatal("record is not private", err)
		}
		if err := b.Create(record, []byte("replacement")); !errors.Is(err, ErrExists) {
			t.Fatal("record changed", err)
		}
		got, err := b.Load(record)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("record bytes changed", err)
		}
		clear(got)
	}
	if err := b.Create(renewalRecord("candidate", 1), make([]byte, maxRecordSize+1)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("oversized record accepted", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load(pendingRecord); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed backend returned data", err)
	}
	reopened, err := OpenNative(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, err := reopened.Load(pendingRecord); err != nil || !bytes.Equal(got, []byte("owned private identity bytes for pending")) {
		clear(got)
		t.Fatal("restart lost persisted data", err)
	} else {
		clear(got)
	}
}

func TestLinuxEncryptedBackendConcurrentHandlesHaveOneCompleteWinner(t *testing.T) {
	_, directory := linuxBackendFixture(t)
	var handles []NativeBackend
	for range 12 {
		b, err := OpenNative(directory)
		if err != nil {
			t.Fatal(err)
		}
		handles = append(handles, b)
		defer b.Close()
	}
	start := make(chan struct{})
	results := make(chan error, len(handles))
	for i, b := range handles {
		go func() { <-start; results <- b.Create(pendingRecord, []byte(fmt.Sprintf("owned winner %d", i))) }()
	}
	close(start)
	winners := 0
	for range handles {
		err := <-results
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrExists) {
			t.Fatal("competing publication failed unexpectedly", err)
		}
	}
	if winners != 1 {
		t.Fatal("publication was not exclusive", winners)
	}
	var winner []byte
	for _, b := range handles {
		got, err := b.Load(pendingRecord)
		if err != nil {
			t.Fatal(err)
		}
		if winner == nil {
			winner = got
		} else {
			if !bytes.Equal(winner, got) {
				t.Fatal("handles selected different winners")
			}
			clear(got)
		}
	}
	clear(winner)
	entries, err := os.ReadDir(filepath.Join(directory, linuxRecordDirectory))
	if err != nil || len(entries) != 1 || entries[0].Name() != pendingRecord+linuxRecordSuffix {
		t.Fatal("publication left temporary records", err)
	}
}

func TestLinuxEncryptedBackendSeparateProcessRecoversSameIdentity(t *testing.T) {
	if directory := os.Getenv("OPENUEM_TEST_LINUX_BACKEND_DIRECTORY"); directory != "" {
		cipher := linuxCipherFixture(t)
		cipher.Close()
		b, err := OpenNative(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		got, err := b.Load(pendingRecord)
		if err != nil || string(got) != "owned cross-process record" {
			clear(got)
			t.Fatal("child lost record", err)
		}
		clear(got)
		if err := b.Create(identityRecord, []byte("owned child publication")); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, directory := linuxBackendFixture(t)
	if err := b.Create(pendingRecord, []byte("owned cross-process record")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestLinuxEncryptedBackendSeparateProcessRecoversSameIdentity$")
	cmd.Env = append(os.Environ(), "OPENUEM_TEST_LINUX_BACKEND_DIRECTORY="+directory)
	if err := cmd.Run(); err != nil {
		t.Fatal("owned child failed", err)
	}
	got, err := b.Load(identityRecord)
	if err != nil || string(got) != "owned child publication" {
		clear(got)
		t.Fatal("parent did not recover child record", err)
	}
	clear(got)
}

func TestLinuxEncryptedBackendRejectsCopiedAndTamperedCiphertext(t *testing.T) {
	for _, kind := range []string{"record copy", "installation copy", "tampered", "symlink", "hardlink", "permissions", "foreign owner", "empty", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			b, directory := linuxBackendFixture(t)
			if err := b.Create(pendingRecord, []byte("owned private record")); err != nil {
				t.Fatal(err)
			}
			path := linuxStoredRecord(directory, pendingRecord)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			record := pendingRecord
			switch kind {
			case "record copy":
				record = identityRecord
				err = os.WriteFile(linuxStoredRecord(directory, record), data, 0600)
			case "installation copy":
				other, otherDir := linuxBackendFixture(t)
				b = other
				err = os.WriteFile(linuxStoredRecord(otherDir, record), data, 0600)
			case "tampered":
				data[len(data)-8] ^= 1
				err = os.WriteFile(path, data, 0600)
			case "symlink":
				if err = os.Rename(path, path+".retained"); err == nil {
					err = os.Symlink(path+".retained", path)
				}
			case "hardlink":
				err = os.Link(path, path+".link")
			case "permissions":
				err = os.Chmod(path, 0644)
			case "foreign owner":
				err = os.Chown(path, 65534, 65534)
			case "empty":
				err = os.WriteFile(path, nil, 0600)
			case "oversize":
				err = os.WriteFile(path, make([]byte, maxProtectedSize+1), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := b.Load(record); got != nil || !errors.Is(err, ErrUnavailable) {
				clear(got)
				t.Fatal("unsafe record accepted", err)
			}
		})
	}
}

func TestLinuxEncryptedBackendRejectsUnknownOrUnsafeRecordNamespaces(t *testing.T) {
	for _, kind := range []string{"unknown", "noncanonical", "directory", "foreign temporary", "shared temporary", "temporary symlink", "service lock in credentials"} {
		t.Run(kind, func(t *testing.T) {
			b, directory := linuxBackendFixture(t)
			name := "unknown.cred"
			switch kind {
			case "noncanonical":
				name = "PENDING.cred"
			case "foreign temporary":
				name = ".enrollment-foreign.tmp"
			case "shared temporary", "temporary symlink":
				name = linuxTemporaryPrefix + uuid.NewString() + ".tmp"
			case "service lock in credentials":
				name = serviceLeaseName
			}
			path := filepath.Join(directory, linuxRecordDirectory, name)
			var err error
			if kind == "directory" {
				err = os.Mkdir(path, 0700)
			} else if kind == "temporary symlink" {
				err = os.Symlink("/fixture/absent", path)
			} else {
				mode := os.FileMode(0600)
				if kind == "shared temporary" {
					mode = 0644
				}
				err = os.WriteFile(path, []byte("retained"), mode)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.Load(pendingRecord); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unknown state became missing", err)
			}
			if err := b.Create(pendingRecord, []byte("replacement")); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unknown state authorized publication", err)
			}
			if other, err := OpenNative(directory); other != nil || !errors.Is(err, ErrUnavailable) {
				if other != nil {
					other.Close()
				}
				t.Fatal("restart accepted unknown state", err)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("existing evidence was removed", err)
			}
		})
	}
}

func TestLinuxEncryptedBackendPreservesUnpublishedCrashTemporaries(t *testing.T) {
	b, directory := linuxBackendFixture(t)
	path := filepath.Join(directory, linuxRecordDirectory, linuxTemporaryPrefix+uuid.NewString()+".tmp")
	if err := os.WriteFile(path, []byte("owned incomplete encrypted output"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.Create(pendingRecord, []byte("owned committed keys")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "owned incomplete encrypted output" {
		t.Fatal("unowned temporary was removed or changed", err)
	}
	if got, err := b.Load(pendingRecord); err != nil || string(got) != "owned committed keys" {
		clear(got)
		t.Fatal(err)
	} else {
		clear(got)
	}
}

func TestLinuxEncryptedBackendRetainsPartialRestoreAndRuntimeBarriers(t *testing.T) {
	pending := restorePendingFixture(t)
	for _, record := range []string{recipientRecord, rotationRecord(true, enrollment.MaxRotationAttempts), softwareRecord("result", MaxSoftwareAttempts), renewalRecord("candidate", MaxIdentityRenewalAttempts)} {
		t.Run(record, func(t *testing.T) {
			b, _ := linuxBackendFixture(t)
			runRetainedSecurityPreventsEnrollment(t, b, record, pending)
		})
	}
	for _, kind := range []string{"netbird-journal", "netbird-preparation", "retained-runtime-file", "unsafe-service-lock"} {
		t.Run(kind, func(t *testing.T) {
			b, directory := linuxBackendFixture(t)
			var err error
			if strings.HasPrefix(kind, "netbird-") {
				err = os.Mkdir(filepath.Join(directory, kind), 0700)
			} else if kind == "unsafe-service-lock" {
				err = os.WriteFile(filepath.Join(directory, serviceLeaseName), []byte("retained"), 0600)
			} else {
				err = os.WriteFile(filepath.Join(directory, kind), []byte("retained"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, withPending := range []bool{false, true} {
				if withPending {
					if err := b.Create(pendingRecord, pending); err != nil {
						t.Fatal(err)
					}
				}
				s := &Store{backend: b}
				called := false
				identity, err := s.enroll(t.Context(), testBootstrap(), func(context.Context, enrollment.Request) (*enrollment.Response, error) {
					called = true
					return nil, enrollment.ErrEnrollmentUnavailable
				})
				if identity != nil || !errors.Is(err, ErrUnavailable) || called {
					t.Fatal("runtime restore bypassed retained state", err, called)
				}
			}
		})
	}
}

func TestLinuxEncryptedBackendCoexistsWithServiceLeaseAndCompletedRuntime(t *testing.T) {
	b, directory := linuxBackendFixture(t)
	lease, err := AcquireServiceLease(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if present, err := b.hasSecurityRecords(); err != nil || present {
		t.Fatal("empty lease became security evidence", err)
	}
	issuer := newFixtureIssuer(t)
	bootstrap := testBootstrap()
	store := &Store{backend: b}
	identity, err := store.enroll(t.Context(), bootstrap, func(_ context.Context, q enrollment.Request) (*enrollment.Response, error) {
		return issuer.claim(bootstrap.Origin, q)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	if err := os.Mkdir(filepath.Join(directory, "netbird-journal"), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Load(); err != nil || got.Response != identity.Response {
		if got != nil {
			got.Close()
		}
		t.Fatal("runtime state invalidated complete credentials", err)
	} else {
		got.Close()
	}
	restarted, err := OpenNative(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if got, err := (&Store{backend: restarted}).Load(); err != nil || got.Response != identity.Response {
		if got != nil {
			got.Close()
		}
		t.Fatal("restart lost complete identity", err)
	} else {
		got.Close()
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(func() error {
		other, err := AcquireServiceLease(directory)
		if other != nil {
			other.Close()
		}
		return err
	}(), ErrServiceBusy) {
		t.Fatal("backend close released another owner's service lease")
	}
	if lease.Validate() != nil {
		t.Fatal("backend changed service lease")
	}
}

func TestLinuxEncryptedBackendCloseJoinsConcurrentAccess(t *testing.T) {
	b, _ := linuxBackendFixture(t)
	if err := b.Create(pendingRecord, []byte("owned")); err != nil {
		t.Fatal(err)
	}
	var joined sync.WaitGroup
	for range 8 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			got, err := b.Load(pendingRecord)
			clear(got)
			if err != nil && !errors.Is(err, ErrUnavailable) {
				t.Error(err)
			}
		}()
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	joined.Wait()
	if err := b.Create(identityRecord, []byte("closed")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed backend published", err)
	}
}

func TestLinuxEncryptedBackendRejectsReplacedProtectedDirectories(t *testing.T) {
	for _, kind := range []string{"installation", "credentials", "installation permissions", "credentials permissions", "symlink parent"} {
		t.Run(kind, func(t *testing.T) {
			b, directory := linuxBackendFixture(t)
			if err := b.Create(pendingRecord, []byte("owned")); err != nil {
				t.Fatal(err)
			}
			path := directory
			if strings.HasPrefix(kind, "credentials") {
				path = filepath.Join(directory, linuxRecordDirectory)
			}
			var err error
			if strings.HasSuffix(kind, "permissions") {
				err = os.Chmod(path, 0755)
			} else {
				err = os.Rename(path, path+".retained")
				if err == nil {
					if kind == "symlink parent" {
						err = os.Symlink(path+".retained", path)
					} else {
						err = os.Mkdir(path, 0700)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := b.Load(pendingRecord); got != nil || !errors.Is(err, ErrUnavailable) {
				clear(got)
				t.Fatal("changed namespace retained authority", err)
			}
			if err := b.Create(identityRecord, []byte("replacement")); !errors.Is(err, ErrUnavailable) {
				t.Fatal("changed namespace accepted a write", err)
			}
		})
	}
}

func TestLinuxEncryptedBackendDetectsEquivalentMetadataCiphertextChanges(t *testing.T) {
	b, directory := linuxBackendFixture(t)
	if err := b.Create(pendingRecord, []byte("owned")); err != nil {
		t.Fatal(err)
	}
	path := linuxStoredRecord(directory, pendingRecord)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	data[len(data)-8] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var equivalent unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &equivalent); err != nil {
		t.Fatal(err)
	}
	if b.matchesFile(pendingRecord+linuxRecordSuffix, file, equivalent, digest) {
		t.Fatal("changed bytes with equivalent metadata were accepted")
	}
}
