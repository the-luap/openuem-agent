package bootstrapinstall

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/artifacts"
	"golang.org/x/sys/unix"
)

func requireLinuxStagingFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENUEM_TEST_LINUX_PACKAGE_SIGNATURES") != "owned-isolated-publishers" {
		t.Skip("requires isolated Linux publisher and package fixtures")
	}
	var fs unix.Statfs_t
	if os.Geteuid() != 0 || unix.Statfs("/fixture", &fs) != nil || fs.Type != unix.TMPFS_MAGIC || !strings.HasPrefix(os.TempDir(), "/fixture") {
		t.Fatal("Linux staging tests require owned private tmpfs storage")
	}
}

func linuxStagingFixture(t *testing.T, format, variant string) *stagingFixture {
	t.Helper()
	requireLinuxStagingFixture(t)
	data, err := os.ReadFile("/fixture/" + variant + "." + format)
	if err != nil {
		t.Fatal(err)
	}
	return newTargetStagingFixture(t, "linux", format, data)
}

func TestLinuxStagingBindsNativePublisherHTTPSAndRelease(t *testing.T) {
	requireLinuxStagingFixture(t)
	for _, format := range []string{"deb", "rpm"} {
		for _, variant := range []string{"signed", "unsigned", "foreign", "body-substitution"} {
			t.Run(format+"/"+variant, func(t *testing.T) {
				source := variant
				if variant == "body-substitution" {
					source = "signed"
				}
				f := linuxStagingFixture(t, format, source)
				if variant == "body-substitution" {
					f.body.Store([]byte("unapproved response body"))
				}
				p, err := StagePackage(context.Background(), f.verified, f.client, f.root, artifacts.Checkpoint{})
				if variant != "signed" {
					if p != nil || !errors.Is(err, ErrPackage) {
						t.Fatal("untrusted native publisher or download admitted", err)
					}
					assertEmptyStaging(t, f.root)
					return
				}
				if err != nil || p == nil || p.Path() == "" || f.requests.Load() != 1 {
					t.Fatal("approved native package was not prepared through HTTPS", err)
				}
				defer p.Close()
				if err = p.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); err != nil {
					t.Fatal("prepared Linux package lost its release binding", err)
				}
				if err = p.Verify(context.Background(), f.verified, artifacts.Checkpoint{Sequence: 43, Digest: strings.Repeat("a", 64)}); !errors.Is(err, artifacts.ErrRollback) {
					t.Fatal("prepared Linux package ignored a later checkpoint", err)
				}
				path := p.Path()
				data, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(data, f.content) {
					t.Fatal("native staging changed approved package bytes", err)
				}
				data[len(data)-1] ^= 1
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err = p.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); !errors.Is(err, ErrPackage) {
					t.Fatal("altered staged bytes retained release authority", err)
				}
				if err = p.Close(); err != nil || p.Path() != "" {
					t.Fatal("owned Linux staging did not close", err)
				}
				assertEmptyStaging(t, f.root)
			})
		}
	}
}

func TestLinuxStagingRejectsUnsafeRootsBeforeDownload(t *testing.T) {
	requireLinuxStagingFixture(t)
	for _, mutation := range []string{"shared-root", "shared-ancestor", "symlink-ancestor", "untrusted-root"} {
		t.Run(mutation, func(t *testing.T) {
			f := linuxStagingFixture(t, "deb", "signed")
			var err error
			switch mutation {
			case "shared-root":
				err = os.Chmod(f.root, 0777)
			case "shared-ancestor":
				err = os.Chmod(filepath.Dir(f.root), 0777)
			case "symlink-ancestor":
				parent := filepath.Dir(f.root)
				if err = os.Rename(parent, parent+".old"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(parent+".old", parent)
			case "untrusted-root":
				err = os.Chown(f.root, 65534, 65534)
			}
			if err != nil {
				t.Fatal(err)
			}
			p, err := StagePackage(context.Background(), f.verified, f.client, f.root, artifacts.Checkpoint{})
			if p != nil || !errors.Is(err, ErrPackage) || f.requests.Load() != 0 {
				t.Fatal("unsafe ancestry allowed a download or staging creation", err)
			}
			assertEmptyStaging(t, f.root)
		})
	}
}

func TestLinuxStagingPreservesReplacedNamespacesAndUnknownFiles(t *testing.T) {
	requireLinuxStagingFixture(t)
	for _, mutation := range []string{"root-inode", "stage-inode", "file-inode", "hardlink", "extra-file"} {
		t.Run(mutation, func(t *testing.T) {
			f := linuxStagingFixture(t, "deb", "signed")
			p, err := StagePackage(context.Background(), f.verified, f.client, f.root, artifacts.Checkpoint{})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			path, stage := p.Path(), p.directory
			preserved := path
			switch mutation {
			case "root-inode", "stage-inode":
				target := stage
				if mutation == "root-inode" {
					target = f.root
				}
				if err = os.Rename(target, target+".old"); err != nil {
					t.Fatal(err)
				}
				err = os.Mkdir(target, 0700)
				preserved = target
			case "file-inode":
				if err = os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				err = os.WriteFile(path, f.content, 0600)
			case "hardlink":
				err = os.Link(path, path+".alias")
			case "extra-file":
				preserved = filepath.Join(stage, "unknown")
				err = os.WriteFile(preserved, []byte("unrelated root-owned evidence"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mutation != "extra-file" {
				if err = p.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); !errors.Is(err, ErrPackage) || p.Path() != "" {
					t.Fatal("changed native staging retained authority", err)
				}
			}
			owner := p.directoryOwner.(*linuxPackageDirectory)
			if err = p.Close(); !errors.Is(err, ErrPackage) || len(owner.directories) != 0 {
				t.Fatal("unsafe cleanup succeeded or retained open ancestors", err)
			}
			if _, err = os.Lstat(preserved); err != nil {
				t.Fatal("cleanup removed an unrelated or ambiguous object", err)
			}
		})
	}
}

func TestLinuxStagingOwnersRemainIndependent(t *testing.T) {
	f := linuxStagingFixture(t, "rpm", "signed")
	first, err := StagePackage(context.Background(), f.verified, f.client, f.root, artifacts.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := StagePackage(context.Background(), f.verified, f.client, f.root, artifacts.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.Path() == second.Path() {
		t.Fatal("different preparations shared one native staging owner")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if err = second.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); err != nil {
		t.Fatal("another preparation's cleanup invalidated this owner", err)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
	assertEmptyStaging(t, f.root)
}
