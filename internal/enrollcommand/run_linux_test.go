package enrollcommand

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"golang.org/x/sys/unix"
)

func requireLinuxEnrollmentFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENUEM_TEST_LINUX_ENROLLMENT") != "owned-isolated-enrollment" {
		t.Skip("requires isolated native Linux enrollment fixture")
	}
	var fs unix.Statfs_t
	machine, err := os.ReadFile("/etc/machine-id")
	if os.Geteuid() != 0 || !strings.HasPrefix(os.TempDir(), "/fixture") || unix.Statfs("/fixture", &fs) != nil || fs.Type != unix.TMPFS_MAGIC || unix.Statfs("/var/lib/systemd", &fs) != nil || fs.Type != unix.TMPFS_MAGIC || err != nil || strings.TrimSpace(string(machine)) != "1643d44b8d204f7087b2a3ec0fcb168d" {
		t.Fatal("native enrollment requires disposable private tmpfs and synthetic host identity")
	}
}

func linuxCommandFixture(t *testing.T, format, variant string) (*commandFixture, dependencies) {
	t.Helper()
	requireLinuxEnrollmentFixture(t)
	f := newTargetCommandFixture(t, "linux", format)
	var err error
	f.packageBytes, err = os.ReadFile("/fixture/" + variant + "." + format)
	if err != nil {
		t.Fatal(err)
	}
	f.agentBytes, err = os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	f.signRelease(t)
	deps := nativeDependencies()
	deps.roots = f.roots // Only the owned loopback TLS issuer is added in this fixture.
	return f, deps
}

func (f *commandFixture) claimCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, request := range f.requests {
		if strings.HasSuffix(request, "/claim") {
			count++
		}
	}
	return count
}

func assertLinuxCommandIdentity(t *testing.T, f *commandFixture, result Result) {
	t.Helper()
	store, err := enrollmentstore.Open(f.options.IdentityDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identity, err := store.Load()
	if err != nil {
		t.Fatal("native encrypted identity did not survive reopening", err)
	}
	defer identity.Close()
	digest := sha256.Sum256(f.agentBytes)
	checkpoint, err := store.Checkpoint()
	if err != nil || checkpoint.Digest != f.release.Digest() || identity.Response.DeviceID != result.DeviceID || identity.ReleaseDigest != result.ReleaseDigest || identity.Platform != "linux" || identity.Architecture != f.config.Architecture || identity.AgentSize != int64(len(f.agentBytes)) || identity.AgentSHA256 != hex.EncodeToString(digest[:]) || identity.Keys == nil || identity.Keys.Certificate == nil || identity.Keys.Broker == nil {
		t.Fatal("native identity lost executable, release, checkpoint or key binding", err)
	}
	entries, err := os.ReadDir(f.options.StagingDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatal("native enrollment left owned package bytes", err)
	}
}

func TestLinuxCommandWithNativeExecutablePackageAndProtectedEnrollment(t *testing.T) {
	requireLinuxEnrollmentFixture(t)
	for _, format := range []string{"deb", "rpm"} {
		t.Run(format, func(t *testing.T) {
			f, deps := linuxCommandFixture(t, format, "signed")
			result, err := run(context.Background(), f.options, deps)
			if err != nil || !result.IdentityReady || f.claimCount() != 1 {
				t.Fatal("native Linux enrollment did not complete exactly one claim", err)
			}
			assertLinuxCommandIdentity(t, f, result)
			again, err := run(context.Background(), f.options, deps)
			if err != nil || again != result || f.claimCount() != 1 {
				t.Fatal("completed Linux enrollment did not reuse its persisted identity", err)
			}
			assertLinuxCommandIdentity(t, f, again)
		})
	}
}

func TestLinuxCommandRejectsNativeTrustAndBindingBeforeClaim(t *testing.T) {
	requireLinuxEnrollmentFixture(t)
	for _, format := range []string{"deb", "rpm"} {
		for _, variant := range []string{"unsigned", "foreign", "agent-bytes", "scope", "config-signature"} {
			t.Run(format+"/"+variant, func(t *testing.T) {
				source := variant
				if variant != "unsigned" && variant != "foreign" {
					source = "signed"
				}
				f, deps := linuxCommandFixture(t, format, source)
				want := ErrPackage
				switch variant {
				case "agent-bytes":
					f.agentBytes = []byte("a different installed image")
					f.signRelease(t)
					want = ErrExecutable
				case "scope":
					f.config.SiteID++
					want = ErrScope
				case "config-signature":
					f.configOverride = []byte(`{"invalid":"signature"}`)
					want = ErrConfiguration
				}
				result, err := run(context.Background(), f.options, deps)
				if !errors.Is(err, want) || result.IdentityReady || f.claimCount() != 0 {
					t.Fatal("invalid native release or authority reached identity issuance", err)
				}
				entries, err := os.ReadDir(filepath.Join(f.options.IdentityDirectory, "credentials-v1"))
				if err != nil || len(entries) != 0 {
					t.Fatal("failed native admission published pending keys", err)
				}
			})
		}
	}
}

func TestLinuxCommandRecoversIssuedIdentityWithOriginalPendingKeys(t *testing.T) {
	f, deps := linuxCommandFixture(t, "deb", "signed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.beforeClaimResponse = cancel
	result, err := run(ctx, f.options, deps)
	if !errors.Is(err, context.Canceled) || result.IdentityReady || f.claimCount() != 1 {
		t.Fatal("canceled issuance did not retain an incomplete attempt", err)
	}
	f.mu.Lock()
	issued := f.issued != nil && f.claimBinding != ""
	originalBinding := f.claimBinding
	f.beforeClaimResponse = nil
	f.mu.Unlock()
	if !issued {
		t.Fatal("fixture canceled before actual certificate issuance")
	}
	result, err = run(context.Background(), f.options, deps)
	if err != nil || !result.IdentityReady || f.claimCount() != 2 {
		t.Fatal("native pending enrollment could not recover the issued identity", err)
	}
	f.mu.Lock()
	sameBinding := f.claimBinding == originalBinding
	f.mu.Unlock()
	if !sameBinding {
		t.Fatal("recovery replaced the already issued device keys")
	}
	assertLinuxCommandIdentity(t, f, result)
}

func TestLinuxCommandRejectsUnsafeInputsAndStagingBeforeNetwork(t *testing.T) {
	requireLinuxEnrollmentFixture(t)
	for _, mutation := range []string{"shared-key-parent", "key-hardlink", "key-symlink", "invitation-owner", "invitation-mode", "staging-parent", "staging-symlink"} {
		t.Run(mutation, func(t *testing.T) {
			f, deps := linuxCommandFixture(t, "deb", "signed")
			want := ErrKeys
			var err error
			switch mutation {
			case "shared-key-parent":
				err = os.Chmod(filepath.Dir(f.options.ReleaseKeysFile), 0777)
			case "key-hardlink":
				err = os.Link(f.options.ReleaseKeysFile, f.options.ReleaseKeysFile+".alias")
			case "key-symlink":
				err = os.Symlink(f.options.ReleaseKeysFile, f.options.ReleaseKeysFile+".alias")
				f.options.ReleaseKeysFile += ".alias"
			case "invitation-owner":
				want = ErrInvitation
				err = os.Chown(f.options.InvitationFile, 65534, 65534)
			case "invitation-mode":
				want = ErrInvitation
				err = os.Chmod(f.options.InvitationFile, 0644)
			case "staging-parent":
				want = ErrPackage
				parent := t.TempDir()
				err = os.Chmod(parent, 0777)
				f.options.StagingDirectory = filepath.Join(parent, "must-not-create")
			case "staging-symlink":
				want = ErrPackage
				err = os.Symlink(t.TempDir(), f.options.StagingDirectory)
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := run(context.Background(), f.options, deps)
			if !errors.Is(err, want) || result.IdentityReady {
				t.Fatal("unsafe native bootstrap input was admitted", err)
			}
			f.mu.Lock()
			requests := len(f.requests)
			f.mu.Unlock()
			if requests != 0 {
				t.Fatal("unsafe native prerequisites reached HTTPS")
			}
			if mutation == "staging-parent" {
				if _, err := os.Lstat(f.options.StagingDirectory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("native preflight created beneath an unsafe ancestor", err)
				}
			}
		})
	}
}

func TestLinuxInputDirectoryRechecksRetainedAncestry(t *testing.T) {
	requireLinuxEnrollmentFixture(t)
	path := filepath.Join(t.TempDir(), "private")
	if err := prepareNativeStaging(path); err != nil {
		t.Fatal(err)
	}
	directory, err := openLinuxInputDirectory(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	if err = os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if directory.valid(false) {
		t.Fatal("retained bootstrap directory accepted a replacement inode")
	}
	input := filepath.Join(path, "bounded")
	if err = os.WriteFile(input, bytes.Repeat([]byte{'a'}, 65), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := readNativeInput(input, 64); data != nil || !errors.Is(err, ErrOptions) {
		t.Fatal("native input exceeded its byte limit")
	}
}
