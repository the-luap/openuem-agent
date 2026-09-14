package packagesignature

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requireLinuxPackageFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENUEM_TEST_LINUX_PACKAGE_SIGNATURES") != "owned-isolated-publishers" {
		t.Skip("requires the isolated native package-signature fixture")
	}
	var filesystem unix.Statfs_t
	if os.Geteuid() != 0 || unix.Statfs("/fixture", &filesystem) != nil || filesystem.Type != unix.TMPFS_MAGIC || !strings.HasPrefix(os.TempDir(), "/fixture") {
		t.Fatal("native package tests require owned root tmpfs storage")
	}
}

func linuxPackageFixture(t *testing.T, format string) (string, string) {
	t.Helper()
	requireLinuxPackageFixture(t)
	root := t.TempDir()
	trust := filepath.Join(root, "trust")
	if err := os.CopyFS(trust, os.DirFS(linuxPublisherRoot)); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stage, "candidate."+format)
	copySignatureFixture(t, "/fixture/signed."+format, path)
	return path, trust
}

func mustLinuxVerifier(t *testing.T, path, format, trust string) *linuxPackageVerifier {
	t.Helper()
	v, err := openLinuxPackageVerifier(path, format, trust)
	if err != nil {
		t.Fatal("open native verifier", err)
	}
	t.Cleanup(v.close)
	return v
}

func TestLinuxPackageSignaturesRequireAuthorizedNativePublisher(t *testing.T) {
	requireLinuxPackageFixture(t)
	// Ambient tool lookup, homes and RPM settings must neither authorize the
	// foreign signer nor prevent the explicitly provisioned native verification.
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".rpmmacros"), []byte("%_pkgverify_level none\n%_pkgverify_flags -1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rpmkeys", "debsig-verify", "gpg", "gpgv"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", home)
	t.Setenv("GNUPGHOME", home)
	t.Setenv("RPM_CONFIGDIR", home)
	for _, format := range []string{"deb", "rpm"} {
		for _, variant := range []string{"signed", "unsigned", "foreign", "tampered"} {
			t.Run(format+"/"+variant, func(t *testing.T) {
				path, _ := linuxPackageFixture(t, format)
				if variant != "signed" {
					source := variant
					if variant == "tampered" {
						source = "signed"
					}
					data, err := os.ReadFile("/fixture/" + source + "." + format)
					if err != nil {
						t.Fatal(err)
					}
					if variant == "tampered" {
						// RPM has a large mutable signature-header reserve before
						// its payload. Change payload bytes, not that reserve; the
						// separate signed release hash covers all package bytes.
						offset := len(data) / 2
						if format == "rpm" {
							offset = len(data) - 1
						}
						data[offset] ^= 1
					}
					if err = os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				err := Verify(context.Background(), path, format)
				if variant == "signed" && err != nil {
					t.Fatal("authorized native signature was rejected", err)
				}
				if variant != "signed" && !errors.Is(err, ErrUntrusted) {
					t.Fatal("unsigned, foreign or altered package was accepted", err)
				}
			})
		}
	}
}

func TestLinuxPackageSignaturesRejectChangedTrustAndBytes(t *testing.T) {
	requireLinuxPackageFixture(t)
	for _, format := range []string{"deb", "rpm"} {
		for _, mutation := range []string{"candidate-bytes", "candidate-inode", "candidate-permissions", "stage-inode", "publisher-bytes", "publisher-inode", "publisher-permissions", "extra-trust-file", "trust-inode"} {
			t.Run(format+"/"+mutation, func(t *testing.T) {
				path, trust := linuxPackageFixture(t, format)
				v := mustLinuxVerifier(t, path, format, trust)
				if err := v.verify(context.Background()); err != nil {
					t.Fatal("initial native verification", err)
				}
				key := filepath.Join(trust, "rpm", "publisher.key")
				if format == "deb" {
					fingerprint, err := os.ReadFile("/fixture/publisher-fingerprint")
					if err != nil {
						t.Fatal(err)
					}
					key = filepath.Join(trust, "deb", "keyrings", strings.TrimSpace(string(fingerprint)), "publisher.gpg")
				}
				var err error
				switch mutation {
				case "candidate-bytes", "publisher-bytes":
					target := path
					if mutation == "publisher-bytes" {
						target = key
					}
					data, e := os.ReadFile(target)
					if e != nil {
						t.Fatal(e)
					}
					data[len(data)/2] ^= 1
					err = os.WriteFile(target, data, 0600)
					// Force the retained metadata to the rewritten file's current
					// values: SHA-256 must still detect equivalent-metadata writes.
					for _, object := range v.objects {
						if filepath.Join(append([]string{"/"}, object.parts...)...) == target {
							if e = unix.Fstat(int(object.file.Fd()), &object.stamp); e != nil {
								t.Fatal(e)
							}
						}
					}
				case "candidate-inode", "publisher-inode":
					target := path
					if mutation == "publisher-inode" {
						target = key
					}
					data, e := os.ReadFile(target)
					if e != nil {
						t.Fatal(e)
					}
					if e = os.WriteFile(target+".replacement", data, 0600); e != nil {
						t.Fatal(e)
					}
					err = os.Rename(target+".replacement", target)
				case "candidate-permissions":
					err = os.Chmod(path, 0644)
				case "publisher-permissions":
					err = os.Chmod(key, 0666)
				case "extra-trust-file":
					err = os.WriteFile(filepath.Join(filepath.Dir(key), "foreign.key"), []byte("unprovisioned object"), 0600)
				case "stage-inode", "trust-inode":
					target := filepath.Dir(path)
					if mutation == "trust-inode" {
						target = trust
					}
					if e := os.Rename(target, target+".old"); e != nil {
						t.Fatal(e)
					}
					err = os.CopyFS(target, os.DirFS(target+".old"))
				}
				if err != nil {
					t.Fatal("mutate fixture", err)
				}
				if err = v.verify(context.Background()); !errors.Is(err, ErrUntrusted) {
					t.Fatal("retained verifier accepted changed trust or package", err)
				}
				v.close()
				if err = v.verify(context.Background()); !errors.Is(err, ErrUntrusted) {
					t.Fatal("closed verifier retained authority", err)
				}
			})
		}
	}
}

func TestLinuxPackageSignaturesRejectUnsafePrerequisites(t *testing.T) {
	requireLinuxPackageFixture(t)
	for _, format := range []string{"deb", "rpm"} {
		for _, mutation := range []string{"missing-trust", "shared-ancestor", "shared-stage", "symlink-candidate", "hardlink-candidate", "fifo-candidate", "missing-key", "unknown-trust-object"} {
			t.Run(format+"/"+mutation, func(t *testing.T) {
				path, trust := linuxPackageFixture(t, format)
				var err error
				switch mutation {
				case "missing-trust":
					err = os.RemoveAll(trust)
				case "shared-ancestor":
					err = os.Chmod(filepath.Dir(trust), 0777)
				case "shared-stage":
					err = os.Chmod(filepath.Dir(path), 0755)
				case "symlink-candidate", "hardlink-candidate", "fifo-candidate":
					if e := os.Rename(path, path+".old"); e != nil {
						t.Fatal(e)
					}
					if mutation == "symlink-candidate" {
						err = os.Symlink(path+".old", path)
					} else if mutation == "hardlink-candidate" {
						err = os.Link(path+".old", path)
					} else {
						err = unix.Mkfifo(path, 0600)
					}
				case "missing-key":
					key := filepath.Join(trust, "rpm", "publisher.key")
					if format == "deb" {
						key = filepath.Join(trust, "deb", "keyrings")
					}
					err = os.RemoveAll(key)
				case "unknown-trust-object":
					err = os.WriteFile(filepath.Join(trust, format, "extra"), []byte("unexpected"), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				v, err := openLinuxPackageVerifier(path, format, trust)
				if v != nil || !errors.Is(err, ErrUntrusted) {
					t.Fatal("unsafe prerequisite accepted", err)
				}
			})
		}
	}
	for _, weakened := range []string{"optional-signature", "unbound-fingerprint", "selection-only", "extra-policy", "fingerprint-alias"} {
		t.Run(weakened, func(t *testing.T) {
			path, trust := linuxPackageFixture(t, "deb")
			fingerprint, err := os.ReadFile("/fixture/publisher-fingerprint")
			if err != nil {
				t.Fatal(err)
			}
			id := strings.TrimSpace(string(fingerprint))
			policyDir := filepath.Join(trust, "deb", "policies", id)
			policy := filepath.Join(policyDir, "openuem.pol")
			data := linuxDebianPolicy(id)
			switch weakened {
			case "optional-signature":
				data = strings.ReplaceAll(data, "Required", "Optional")
			case "unbound-fingerprint":
				data = strings.ReplaceAll(data, " id=\""+id+"\"", "")
			case "selection-only":
				start := strings.Index(data, "  <Verification>")
				data = data[:start] + "</Policy>\n"
			case "extra-policy":
				policy = filepath.Join(policyDir, "extra.pol")
			case "fingerprint-alias":
				err = os.Rename(policyDir, filepath.Join(filepath.Dir(policyDir), id[24:]))
				policy = filepath.Join(filepath.Dir(policyDir), id[24:], "openuem.pol")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(policy, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			v, err := openLinuxPackageVerifier(path, "deb", trust)
			if v != nil || !errors.Is(err, ErrUntrusted) {
				t.Fatal("weakened publisher policy accepted", err)
			}
		})
	}
}

func TestLinuxPackageSignatureCancellationJoinsProcess(t *testing.T) {
	requireLinuxPackageFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pidFile := filepath.Join(t.TempDir(), "child-pid")
	// Only this fixture uses a shell; production runs retained native ELF files.
	command := exec.CommandContext(ctx, "/bin/sh", "-c", `/usr/bin/sleep 60 & child=$!; printf '%s' "$child" > "$1"; wait "$child"`, "fixture", pidFile)
	completed := make(chan error, 1)
	go func() {
		data, err := runLinuxSignatureCheck(ctx, command)
		if len(data) != 0 {
			err = errors.New("cancelled verifier returned diagnostics")
		}
		completed <- err
	}()
	var child int
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			child, _ = strconv.Atoi(string(bytes.TrimSpace(data)))
			if child > 0 {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	err := <-completed
	if child == 0 || !errors.Is(err, context.Canceled) || command.ProcessState == nil {
		t.Fatal("native process cancellation did not join the owned verifier", err)
	}
	requireLinuxSignatureChildGone(t, child)
}

func requireLinuxSignatureChildGone(t *testing.T, child int) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		if errors.Is(unix.Kill(child, 0), unix.ESRCH) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("native verification descendant survived cancellation")
}

func TestLinuxPackageSignatureLeaderExitTerminatesDescendant(t *testing.T) {
	requireLinuxPackageFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pidFile := filepath.Join(t.TempDir(), "child-pid")
	command := exec.CommandContext(ctx, "/bin/sh", "-c", `/usr/bin/sleep 60 >/dev/null 2>&1 & child=$!; printf '%s' "$child" > "$1"; exit 0`, "fixture", pidFile)
	data, err := runLinuxSignatureCheck(ctx, command)
	if err != nil || len(data) != 0 || command.ProcessState == nil || ctx.Err() != nil {
		t.Fatal("early verifier exit was not joined", err)
	}
	pid, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	child, err := strconv.Atoi(string(pid))
	if err != nil || child < 1 {
		t.Fatal("invalid owned descendant")
	}
	requireLinuxSignatureChildGone(t, child)
}

func TestLinuxPackageSignatureNativeProcessOutputBounds(t *testing.T) {
	requireLinuxPackageFixture(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"pass", "overflow", "error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "openuem-signature-process-fixture", mode)
			data, err := runLinuxSignatureCheck(ctx, command)
			if command.ProcessState == nil {
				t.Fatal("native process output check was not joined")
			}
			if mode == "pass" {
				if err != nil || string(data) != "verified\n" {
					t.Fatal("native process success output lost", err)
				}
			} else if !errors.Is(err, ErrUntrusted) || data != nil {
				t.Fatal("native process exposed failed or unbounded output", err)
			}
		})
	}
}
