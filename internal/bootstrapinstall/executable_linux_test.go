package bootstrapinstall

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/artifacts"
	"golang.org/x/sys/unix"
)

func requireLinuxExecutableFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENUEM_TEST_LINUX_EXECUTABLE") != "owned-isolated-image" {
		t.Skip("requires isolated root native executable fixture")
	}
	var fs unix.Statfs_t
	if os.Geteuid() != 0 || unix.Statfs("/fixture", &fs) != nil || fs.Type != unix.TMPFS_MAGIC || !strings.HasPrefix(os.TempDir(), "/fixture") {
		t.Fatal("Linux image tests require owned private tmpfs storage")
	}
}

func linuxImageCopy(t *testing.T) (string, []byte) {
	t.Helper()
	requireLinuxExecutableFixture(t)
	data, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "installation")
	if err = os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "openuem-agent")
	if err = os.WriteFile(path, data, 0755); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func TestLinuxRunningImageMatchesKernelIdentity(t *testing.T) {
	requireLinuxExecutableFixture(t)
	e, err := OpenRunningAgent()
	if err != nil {
		t.Fatal("open actual running Linux image", err)
	}
	defer e.Close()
	if path, err := e.InstalledPath(); err != nil || path == "" {
		t.Fatal("running executable lost its retained installation path", err)
	}
	path, data := linuxImageCopy(t)
	for _, format := range []string{"deb", "rpm"} {
		f := newTargetStagingFixture(t, "linux", format, []byte("separate inert installer"), data)
		if err = e.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); err != nil {
			t.Fatal("running image failed independently signed Linux binding", err)
		}
		generic, err := openAgentExecutable(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = generic.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); !errors.Is(err, ErrPackage) {
			t.Fatal("generic file open authorized a Linux running image", err)
		}
		generic.Close()
	}
	image, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if copied, err := openLinuxCodeIdentity(path, image); copied != nil || !errors.Is(err, ErrPackage) {
		t.Fatal("identical copied bytes were mistaken for the running kernel image", err)
	}
	sum := sha256.Sum256(data)
	if err = e.VerifyStoredBinding(context.Background(), int64(len(data)), hex.EncodeToString(sum[:])); err != nil {
		t.Fatal("retained Linux image lost its protected completed-enrollment binding", err)
	}
	owner := e.code.(*linuxCodeIdentity)
	if err = e.Close(); err != nil || owner.image != nil || len(owner.directories) != 0 {
		t.Fatal("Linux image close did not release kernel/ancestry handles", err)
	}
	if _, err = e.InstalledPath(); !errors.Is(err, ErrPackage) {
		t.Fatal("closed image retained an installed path", err)
	}
}

func TestLinuxExecutableRejectsUnsafeImages(t *testing.T) {
	requireLinuxExecutableFixture(t)
	for _, mutation := range []string{"symlink", "ancestor-symlink", "hardlink", "fifo", "shared-parent", "special-parent", "untrusted-owner", "shared-image", "special-image", "no-execute", "truncated", "wrong-magic", "wrong-class", "wrong-endian", "wrong-architecture", "relocatable", "wrong-header-size"} {
		t.Run(mutation, func(t *testing.T) {
			path, data := linuxImageCopy(t)
			image, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			// Opening the private test image before mutation also proves unsafe
			// path types are rejected without blocking on FIFO or following links.
			switch mutation {
			case "symlink", "hardlink", "fifo":
				if err = os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if mutation == "symlink" {
					err = os.Symlink(path+".old", path)
				} else if mutation == "hardlink" {
					err = os.Link(path+".old", path)
				} else {
					err = unix.Mkfifo(path, 0600)
				}
			case "ancestor-symlink":
				parent := filepath.Dir(path)
				if err = os.Rename(parent, parent+".old"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(parent+".old", parent)
			case "shared-parent":
				err = os.Chmod(filepath.Dir(path), 0777)
			case "special-parent":
				err = os.Chmod(filepath.Dir(path), 0755|os.ModeSticky)
			case "untrusted-owner":
				err = os.Chown(path, 65534, 65534)
			case "shared-image":
				err = os.Chmod(path, 0777)
			case "special-image":
				err = os.Chmod(path, 0755|os.ModeSetuid)
			case "no-execute":
				err = os.Chmod(path, 0644)
			default:
				switch mutation {
				case "truncated":
					data = data[:63]
				case "wrong-magic":
					data[0] ^= 1
				case "wrong-class":
					data[4] = 1
				case "wrong-endian":
					data[5] = 2
				case "wrong-architecture":
					binary.LittleEndian.PutUint16(data[18:20], 40)
				case "relocatable":
					binary.LittleEndian.PutUint16(data[16:18], 1)
				case "wrong-header-size":
					binary.LittleEndian.PutUint16(data[52:54], 32)
				}
				err = os.WriteFile(path, data, 0755)
			}
			if err != nil {
				image.Close()
				t.Fatal("mutate isolated image", err)
			}
			if e, err := openLinuxCodeIdentity(path, image); e != nil || !errors.Is(err, ErrPackage) {
				t.Fatal("unsafe native image or path accepted", err)
			}
		})
	}
}

func TestLinuxExecutableRejectsChangedImageAndAncestors(t *testing.T) {
	requireLinuxExecutableFixture(t)
	for _, mutation := range []string{"bytes", "permissions", "image-inode", "ancestor-inode", "ancestor-permissions"} {
		t.Run(mutation, func(t *testing.T) {
			path, data := linuxImageCopy(t)
			image, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			e, err := openLinuxCodeIdentity(path, image)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			f := newTargetStagingFixture(t, "linux", "deb", []byte("separate installer"), data)
			if err = e.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); err != nil {
				t.Fatal("initial native fixture binding", err)
			}
			switch mutation {
			case "bytes":
				data[len(data)-1] ^= 1
				err = os.WriteFile(path, data, 0755)
				// Exercise content integrity independently of timestamp resolution.
				owner := e.code.(*linuxCodeIdentity)
				if err == nil {
					err = unix.Fstat(int(e.file.Fd()), &owner.stamp)
				}
			case "permissions":
				err = os.Chmod(path, 0777)
			case "image-inode":
				if err = os.WriteFile(path+".new", data, 0755); err != nil {
					t.Fatal(err)
				}
				err = os.Rename(path+".new", path)
			case "ancestor-inode":
				parent := filepath.Dir(path)
				if err = os.Rename(parent, parent+".old"); err != nil {
					t.Fatal(err)
				}
				err = os.CopyFS(parent, os.DirFS(parent+".old"))
			case "ancestor-permissions":
				err = os.Chmod(filepath.Dir(path), 0777)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = e.InstalledPath(); !errors.Is(err, ErrPackage) {
				t.Fatal("changed Linux image retained path authority", err)
			}
			if err = e.Verify(context.Background(), f.verified, artifacts.Checkpoint{}); !errors.Is(err, ErrPackage) {
				t.Fatal("changed Linux image retained release authority", err)
			}
		})
	}
}
