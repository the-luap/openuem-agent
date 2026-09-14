package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

const linuxCredentialFixtureMachine = "1643d44b8d204f7087b2a3ec0fcb168d"

func linuxCipherFixture(t *testing.T) *linuxCredentialCipher {
	t.Helper()
	if os.Getenv("OPENUEM_TEST_LINUX_CREDS") != "owned-isolated-host-key" {
		t.Skip("requires isolated native systemd credential fixture")
	}
	machine, err := os.ReadFile("/etc/machine-id")
	var fs unix.Statfs_t
	if err != nil || strings.TrimSpace(string(machine)) != linuxCredentialFixtureMachine || os.Geteuid() != 0 || unix.Statfs("/var/lib/systemd", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Fatal("refusing credential tests outside the owned root fixture")
	}
	cipher, err := openLinuxCredentialCipher()
	if err != nil {
		t.Fatal("native host credential provider is unavailable", err)
	}
	t.Cleanup(func() {
		if err := cipher.Close(); err != nil {
			t.Error(err)
		}
	})
	return cipher
}

func TestLinuxHostCredentialFormatRejectsNullUnknownAndAmbiguousData(t *testing.T) {
	valid := append(append([]byte{}, linuxHostCredentialID...), make([]byte, 64)...)
	encoded := []byte(base64.StdEncoding.EncodeToString(valid))
	wrapped := append(append([]byte{}, encoded[:32]...), '\n')
	wrapped = append(wrapped, encoded[32:]...)
	if got, err := linuxHostCredential(wrapped); err != nil || !bytes.Equal(got, encoded) {
		t.Fatal("native wrapped host encoding was lost", err)
	}
	for _, kind := range []string{"null", "unknown", "truncated", "corrupt", "space", "CRLF", "oversize", "empty"} {
		t.Run(kind, func(t *testing.T) {
			data := append([]byte{}, encoded...)
			switch kind {
			case "null":
				raw := append([]byte{}, valid...)
				copy(raw, []byte{0x05, 0x84, 0x69, 0xda, 0xf6, 0xf5, 0x43, 0x24, 0x80, 0x05, 0x49, 0xda, 0x0f, 0x8e, 0xa2, 0xfb})
				data = []byte(base64.StdEncoding.EncodeToString(raw))
			case "unknown":
				data[0] = 'A'
			case "truncated":
				data = data[:20]
			case "corrupt":
				data[20] = '!'
			case "space":
				data = append(data, ' ')
			case "CRLF":
				data = append(data, '\r', '\n')
			case "oversize":
				data = bytes.Repeat([]byte{'A'}, maxProtectedSize+1)
			case "empty":
				data = nil
			}
			if got, err := linuxHostCredential(data); got != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("unsafe credential format accepted", err)
			}
		})
	}
}

func TestLinuxNativeHostCredentialsBindContextAndRetainExactBoundedPlaintext(t *testing.T) {
	cipher := linuxCipherFixture(t)
	directory := "/var/lib/openuem/owned-identity"
	for _, size := range []int{1, 128, maxRecordSize} {
		plain := bytes.Repeat([]byte{'x'}, size)
		plain[0] = 0
		sealed, err := cipher.protect(t.Context(), directory, "pending", plain, true)
		if err != nil || bytes.Contains(sealed, plain) {
			t.Fatal("native encryption failed or retained plaintext", err)
		}
		got, err := cipher.protect(t.Context(), directory, "pending", sealed, false)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("native decryption changed bytes", err)
		}
		clear(got)
		for _, target := range [][2]string{{directory, "identity"}, {directory + "-other", "pending"}} {
			if got, err := cipher.protect(t.Context(), target[0], target[1], sealed, false); got != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("foreign purpose was accepted", err)
			}
		}
		decoded, err := base64.StdEncoding.DecodeString(string(sealed))
		if err != nil {
			t.Fatal(err)
		}
		decoded[len(decoded)-1] ^= 1
		tampered := []byte(base64.StdEncoding.EncodeToString(decoded))
		if got, err := cipher.protect(t.Context(), directory, "pending", tampered, false); got != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("native integrity failure was ignored", err)
		}
	}
	for _, record := range []string{"../pending", "", "unknown"} {
		if got, err := cipher.protect(t.Context(), directory, record, []byte("owned"), true); got != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid record accepted", err)
		}
	}
	if got, err := cipher.protect(t.Context(), directory, "pending", make([]byte, maxRecordSize+1), true); got != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("oversized plaintext accepted", err)
	}
}

func TestLinuxNativeHostCredentialsRejectNamelessAndForeignEnvelopes(t *testing.T) {
	cipher := linuxCipherFixture(t)
	directory := "/var/lib/openuem/owned-identity"
	name, err := linuxCredentialName(directory, "pending")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"nameless", "foreign-envelope", "null-key"} {
		t.Run(kind, func(t *testing.T) {
			args := []string{"encrypt", "--with-key=host", "--name=" + name, "-", "-"}
			if kind == "nameless" {
				args[2] = "--name="
			}
			if kind == "null-key" {
				args[1] = "--with-key=auto-initrd"
			}
			cmd := exec.CommandContext(t.Context(), "/usr/bin/systemd-creds", args...)
			cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_LOG_TARGET=null"}
			cmd.Stdin = strings.NewReader("owned plaintext without the required envelope")
			sealed, err := cmd.Output()
			if err != nil {
				t.Fatal("owned native negative fixture failed", err)
			}
			if got, err := cipher.protect(t.Context(), directory, "pending", sealed, false); got != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("unsafe native envelope accepted", err)
			}
		})
	}
}

func TestLinuxNativeHostCredentialsIgnoreAmbientOverridesAndRecheckKeyOwnership(t *testing.T) {
	cipher := linuxCipherFixture(t)
	t.Setenv("SYSTEMD_CREDENTIAL_SECRET", "/fixture/foreign-secret")
	t.Setenv("LD_PRELOAD", "/fixture/foreign-library")
	sealed, err := cipher.protect(t.Context(), "/var/lib/openuem/owned", "pending", []byte("owned"), true)
	if err != nil {
		t.Fatal("ambient override changed the native provider", err)
	}
	path := "/var/lib/systemd/credential.secret"
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0400)
	if got, err := cipher.protect(t.Context(), "/var/lib/openuem/owned", "pending", sealed, false); got != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("changed host key ownership was accepted", err)
	}
	if other, err := openLinuxCredentialCipher(); other != nil || !errors.Is(err, ErrUnavailable) {
		if other != nil {
			other.Close()
		}
		t.Fatal("shared host key accepted", err)
	}
}

func TestLinuxNativeHostCredentialsJoinCloseAndRejectCancelledWork(t *testing.T) {
	cipher := linuxCipherFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := cipher.protect(ctx, "/var/lib/openuem/owned", "pending", []byte("owned"), true); got != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled operation ran", err)
	}
	var joined sync.WaitGroup
	for range 8 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			plain, err := cipher.protect(t.Context(), "/var/lib/openuem/owned", "pending", []byte("owned"), true)
			clear(plain)
			if err != nil && !errors.Is(err, ErrUnavailable) {
				t.Error(err)
			}
		}()
	}
	if err := cipher.Close(); err != nil {
		t.Fatal(err)
	}
	joined.Wait()
	if got, err := cipher.protect(t.Context(), "/var/lib/openuem/owned", "pending", []byte("owned"), true); got != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed provider remained available", err)
	}
}

func TestLinuxNativeCredentialFilesRejectUnsafeAndReplacedObjects(t *testing.T) {
	linuxCipherFixture(t)
	for _, kind := range []string{"permissions", "foreign owner", "shared parent", "symlink", "hardlink", "replacement", "changed contents"} {
		t.Run(kind, func(t *testing.T) {
			directory := linuxServiceLeaseDirectory(t)
			path := directory + "/owned-key"
			if err := os.WriteFile(path, make([]byte, 4112), 0400); err != nil {
				t.Fatal(err)
			}
			guard, err := openLinuxCredentialFile(path, true)
			if err != nil {
				t.Fatal(err)
			}
			defer guard.close()
			switch kind {
			case "permissions":
				err = os.Chmod(path, 0600)
			case "foreign owner":
				err = os.Chown(path, 65534, 65534)
			case "shared parent":
				err = os.Chmod(directory, 0777)
			case "hardlink":
				err = os.Link(path, path+".link")
			case "symlink", "replacement":
				if err = os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(path+".retained", path)
				} else {
					err = os.WriteFile(path, make([]byte, 4112), 0400)
				}
			case "changed contents":
				err = os.WriteFile(path, bytes.Repeat([]byte{'x'}, 4112), 0400)
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "changed contents" {
				// Force equivalent metadata to cover coarse filesystem clocks reliably.
				// The original content fingerprint must still reject the new bytes.
				if err := unix.Fstat(int(guard.file.Fd()), &guard.stamp); err != nil {
					t.Fatal(err)
				}
			}
			if guard.valid() {
				t.Fatal("changed key or namespace remained authoritative")
			}
			if kind != "replacement" && kind != "changed contents" {
				if other, err := openLinuxCredentialFile(path, true); other != nil || !errors.Is(err, ErrUnavailable) {
					if other != nil {
						other.close()
					}
					t.Fatal("unsafe key was accepted", err)
				}
			}
		})
	}
}

func TestLinuxNativeHostCredentialOutputIsBoundedAndJoined(t *testing.T) {
	cipher := linuxCipherFixture(t)
	original := cipher.tool
	defer original.close()
	// A root-owned native ELF fixture emits unbounded non-secret output. The
	// production constructor only selects /usr/bin/systemd-creds.
	var err error
	cipher.tool, err = openLinuxCredentialFile("/usr/bin/yes", false)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cipher.protect(t.Context(), "/var/lib/openuem/owned", "pending", []byte("owned"), true); got != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("unbounded native output was accepted", err)
	}
	if err := cipher.Close(); err != nil {
		t.Fatal(err)
	}
}
