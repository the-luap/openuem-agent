package packagesignature

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
	"golang.org/x/sys/unix"
)

const linuxPublisherRoot = "/etc/openuem/package-signing"

type linuxPackageVerifier struct {
	objects   []*linuxSignatureFile
	tool      *linuxSignatureFile
	candidate *linuxSignatureFile
	args      []string
	format    string
}

func verifyNative(ctx context.Context, path, format string) error {
	v, err := openLinuxPackageVerifier(path, format, linuxPublisherRoot)
	if err != nil {
		return ErrUntrusted
	}
	defer v.close()
	return v.verify(ctx)
}

func openLinuxPackageVerifier(path, format, trustRoot string) (*linuxPackageVerifier, error) {
	v := &linuxPackageVerifier{format: format}
	accepted := false
	defer func() {
		if !accepted {
			v.close()
		}
	}()
	var err error
	v.candidate, err = v.open(path, artifacts.MaxPackageSize, false, false, true)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(trustRoot, format)
	switch format {
	case "rpm":
		v.tool, err = v.open("/usr/bin/rpmkeys", 32<<20, false, true, false)
		if err != nil {
			return nil, err
		}
		if _, err = v.directory(base, []string{"publisher.key"}); err != nil {
			return nil, err
		}
		if _, err = v.open(filepath.Join(base, "publisher.key"), 64<<10, false, false, false); err != nil {
			return nil, err
		}
		// A private filesystem keyring excludes the system RPM database. Explicit
		// empty configuration files exclude user macros, plugins and weaker local
		// verification defaults. Both signature and payload digests are required.
		v.args = []string{"--macros", "/dev/null", "--rcfile", "/dev/null", "--define", "_keyring fs", "--define", "_keyringpath " + base, "--define", "_pkgverify_level all", "--define", "_pkgverify_flags 0", "--checksig", "/proc/self/fd/4"}
	case "deb":
		v.tool, err = v.open("/usr/bin/debsig-verify", 32<<20, false, true, false)
		if err != nil {
			return nil, err
		}
		// debsig-verify invokes the system OpenPGP programs internally. Pin and
		// revalidate both versions; PATH contains only their trusted directory.
		for _, tool := range []string{"/usr/bin/gpg", "/usr/bin/gpgv"} {
			if _, err = v.open(tool, 32<<20, false, true, false); err != nil {
				return nil, err
			}
		}
		if err = v.debianTrust(base); err != nil {
			return nil, err
		}
		v.args = []string{"--policies-dir", filepath.Join(base, "policies"), "--keyrings-dir", filepath.Join(base, "keyrings"), "--use-policy", "openuem.pol", "/proc/self/fd/4"}
	default:
		return nil, ErrUntrusted
	}
	if !v.valid() {
		return nil, ErrUntrusted
	}
	accepted = true
	return v, nil
}

func (v *linuxPackageVerifier) open(path string, limit int64, directory, executable, private bool) (*linuxSignatureFile, error) {
	f, err := openLinuxSignatureFile(path, limit, directory, executable, private)
	if err == nil {
		v.objects = append(v.objects, f)
	}
	return f, err
}

func (v *linuxPackageVerifier) directory(path string, names []string) (*linuxSignatureFile, error) {
	f, err := v.open(path, 0, true, false, false)
	if err != nil || names != nil && !slices.Equal(names, f.names) {
		return nil, ErrUntrusted
	}
	return f, nil
}

func (v *linuxPackageVerifier) debianTrust(base string) error {
	if _, err := v.directory(base, []string{"keyrings", "policies"}); err != nil {
		return err
	}
	policies, err := v.directory(filepath.Join(base, "policies"), nil)
	if err != nil || len(policies.names) == 0 {
		return ErrUntrusted
	}
	if _, err = v.directory(filepath.Join(base, "keyrings"), policies.names); err != nil {
		return err
	}
	for _, fingerprint := range policies.names {
		if len(fingerprint) != 40 || strings.Trim(fingerprint, "0123456789ABCDEF") != "" {
			return ErrUntrusted
		}
		policyDir := filepath.Join(base, "policies", fingerprint)
		keyDir := filepath.Join(base, "keyrings", fingerprint)
		if _, err = v.directory(policyDir, []string{"openuem.pol"}); err != nil {
			return err
		}
		if _, err = v.directory(keyDir, []string{"publisher.gpg"}); err != nil {
			return err
		}
		policy, err := v.open(filepath.Join(policyDir, "openuem.pol"), 4096, false, false, false)
		if err != nil {
			return err
		}
		data := make([]byte, policy.stamp.Size)
		if _, err = policy.file.ReadAt(data, 0); err != nil || string(data) != linuxDebianPolicy(fingerprint) {
			return ErrUntrusted
		}
		if _, err = v.open(filepath.Join(keyDir, "publisher.gpg"), 64<<10, false, false, false); err != nil {
			return err
		}
	}
	return nil
}

// One exact policy prevents selection-only, optional signatures, an unbound
// keyring, or an extra policy from weakening publisher authorization. debsig
// selection alone checks signature presence, never cryptographic validity.
func linuxDebianPolicy(fingerprint string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE Policy SYSTEM "https://www.debian.org/debsig/1.0/policy.dtd">
<Policy xmlns="https://www.debian.org/debsig/1.0/">
  <Origin Name="OpenUEM" id="%[1]s" Description="OpenUEM package publisher"/>
  <Selection><Required Type="origin" File="publisher.gpg" id="%[1]s"/></Selection>
  <Verification><Required Type="origin" File="publisher.gpg" id="%[1]s"/></Verification>
</Policy>
`, fingerprint)
}

func (v *linuxPackageVerifier) valid() bool {
	for _, f := range v.objects {
		if !f.valid() {
			return false
		}
	}
	return len(v.objects) != 0
}

func (v *linuxPackageVerifier) close() {
	for i := len(v.objects) - 1; i >= 0; i-- {
		v.objects[i].close()
	}
	v.objects = nil
}

func (v *linuxPackageVerifier) verify(ctx context.Context) error {
	if ctx == nil {
		return ErrUntrusted
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !v.valid() {
		return ErrUntrusted
	}
	command := exec.CommandContext(ctx, "/proc/self/fd/3", v.args...)
	command.Args[0] = filepath.Base(v.tool.file.Name())
	command.ExtraFiles = []*os.File{v.tool.file, v.candidate.file}
	command.Env = []string{"PATH=/usr/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent", "GNUPGHOME=/nonexistent"}
	data, err := runLinuxSignatureCheck(ctx, command)
	defer clear(data)
	if err != nil {
		return err
	}
	// Older RPM versions can report success for unsigned digests. Require the
	// native signature result as well as mandatory verification flags and exit.
	if v.format == "rpm" && !bytes.Equal(data, []byte("/proc/self/fd/4: digests signatures OK\n")) {
		return ErrUntrusted
	}
	if !v.valid() {
		return ErrUntrusted
	}
	return ctx.Err()
}

func runLinuxSignatureCheck(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	var output boundedOutput
	command.Stdout, command.Stderr = &output, &output
	command.Stdin = nil
	command.WaitDelay = time.Second
	command.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
	var mu sync.Mutex
	owned := true
	command.Cancel = func() error {
		mu.Lock()
		defer mu.Unlock()
		if !owned {
			return os.ErrProcessDone
		}
		err := unix.Kill(-command.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	err := command.Start()
	if err == nil {
		// Retain the waitable leader until its process group has been stopped.
		// This covers a native helper that exits before a descendant closes its
		// pipes, without ever signalling a recycled PID after Cmd.Wait reaps it.
		var status unix.Siginfo
		for {
			err = unix.Waitid(unix.P_PID, command.Process.Pid, &status, unix.WEXITED|unix.WNOWAIT, nil)
			if !errors.Is(err, unix.EINTR) {
				break
			}
		}
		mu.Lock()
		if err == nil {
			if e := unix.Kill(-command.Process.Pid, unix.SIGKILL); e != nil && !errors.Is(e, unix.ESRCH) {
				err = e
			}
		} else {
			command.Process.Kill()
		}
		owned = false
		mu.Unlock()
		if e := command.Wait(); err == nil {
			err = e
		}
	}
	if ctx.Err() != nil {
		clear(output.data)
		return nil, ctx.Err()
	}
	if err != nil || output.overflow {
		clear(output.data)
		return nil, ErrUntrusted
	}
	return output.data, nil
}

func HandleHelper(args []string) (bool, int) {
	if len(args) > 0 && args[0] == helperArgument {
		return true, 1
	}
	return false, 0
}
