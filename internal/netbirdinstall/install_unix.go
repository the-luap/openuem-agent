//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func runNativeInstaller(parent context.Context, executable string, args []string) error {
	if parent == nil || !filepath.IsAbs(executable) {
		return ErrInstallation
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	// Null-device streams cannot retain private diagnostics or block pipe drains.
	// Killing and joining this command does not assert rollback by installd.
	command.Stdin, command.Stdout, command.Stderr = nil, nil, nil
	command.WaitDelay = time.Second
	if command.Run() != nil || ctx.Err() != nil {
		return ErrInstallation
	}
	return nil
}

func nativeInstallationPreflight(ctx context.Context, files map[string]installedFile) error {
	for name := range files {
		if _, err := installedPath(ctx, "/", name, 0, true); err != nil {
			return err
		}
	}
	return nativeCLIPath(ctx, "/", 0, true)
}

func nativeInstallationSource(ctx context.Context, path string) error {
	return installationSourcePath(ctx, path, 0)
}

// Validate the complete source ancestry, including extended ACLs. Only the
// fixed root-owned macOS /var, /tmp and /etc aliases may redirect traversal;
// arbitrary intermediate symlinks cannot redefine the protected package path.
func installationSourcePath(ctx context.Context, path string, owner uint32) error {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInstallation
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for len(parts) > 0 {
		current = filepath.Join(current, parts[0])
		parts = parts[1:]
		info, err := os.Lstat(current)
		if err != nil {
			return ErrInstallation
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != owner {
			return ErrInstallation
		}
		if info.Mode()&os.ModeSymlink != 0 {
			alias := map[string]string{"/var": "/private/var", "/tmp": "/private/tmp", "/etc": "/private/etc"}[current]
			target, err := os.Readlink(current)
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(current), target)
			}
			if alias == "" || stat.Uid != 0 || err != nil || filepath.Clean(target) != alias {
				return ErrInstallation
			}
			parts = append(strings.Split(strings.TrimPrefix(alias, "/"), "/"), parts...)
			current = "/"
			continue
		}
		stickyRoot := info.IsDir() && stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
		if !stickyRoot && (info.Mode().Perm()&0002 != 0 || info.Mode().Perm()&0020 != 0 && stat.Gid != 80) || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || !trustedNativeACL(current) {
			return ErrInstallation
		}
		if len(parts) == 0 {
			if !info.Mode().IsRegular() || stat.Nlink != 1 || info.Mode().Perm()&0077 != 0 {
				return ErrInstallation
			}
			return nil
		}
		if !info.IsDir() {
			return ErrInstallation
		}
	}
	return ErrInstallation
}

func nativeInstallationResult(ctx context.Context, descriptor packageapi.Package, files map[string]installedFile) error {
	if err := readNativePackage(ctx, "/usr/sbin/pkgutil", []string{"--volume", "/", "--pkg-info-plist", descriptor.PackageID}, 32<<10, func(reader io.Reader) error { return verifyNativeReceipt(reader, descriptor) }); err != nil {
		return ErrInstallation
	}
	if err := verifyInstalledFiles(ctx, "/", files, 0); err != nil {
		return err
	}
	return nativeCLIPath(ctx, "/", 0, false)
}

// The vendor preinstall script executes this existing path, and later agent
// commands use it too. Reject other distributions or user-controlled links
// before mutation; after installation require the exact vendor app link.
func nativeCLIPath(ctx context.Context, root string, owner uint32, allowMissing bool) error {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return ErrInstallation
	}
	current := root
	for _, part := range []string{"usr", "local", "bin", "netbird"} {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || ctx.Err() != nil {
			return ErrInstallation
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != owner {
			return ErrInstallation
		}
		if part == "netbird" {
			if info.Mode()&os.ModeSymlink == 0 || stat.Nlink != 1 {
				return ErrInstallation
			}
			target, err := os.Readlink(current)
			if err != nil || target != "/Applications/NetBird.app/Contents/MacOS/netbird" {
				return ErrInstallation
			}
			return nil
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0002 != 0 || info.Mode().Perm()&0020 != 0 && stat.Gid != 80 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || !trustedNativeACL(current) {
			return ErrInstallation
		}
	}
	return ErrInstallation
}

// installedPath rejects linked or untrusted ancestors without repairing them.
// Root and the macOS administrator group may maintain system application paths;
// arbitrary user ownership or world write access cannot become installer input.
func installedPath(ctx context.Context, root, name string, owner uint32, allowMissing bool) (os.FileInfo, error) {
	if ctx.Err() != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(name, "Applications/NetBird.app/") || filepath.Clean(name) != name || strings.Contains(name, "\\") {
		return nil, ErrInstallation
	}
	current := root
	parts := strings.Split(name, "/")
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, ErrInstallation
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != owner || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0002 != 0 || info.Mode().Perm()&0020 != 0 && stat.Gid != 80 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || !trustedNativeACL(current) {
			return nil, ErrInstallation
		}
		if index == len(parts)-1 {
			if !info.Mode().IsRegular() || stat.Nlink != 1 {
				return nil, ErrInstallation
			}
			return info, nil
		}
		if !info.IsDir() {
			return nil, ErrInstallation
		}
	}
	return nil, ErrInstallation
}

func verifyInstalledFiles(ctx context.Context, root string, files map[string]installedFile, owner uint32) error {
	if len(files) == 0 || len(files) > 1024 {
		return ErrInstallation
	}
	for name, expected := range files {
		info, err := installedPath(ctx, root, name, owner, false)
		if err != nil || info.Size() != expected.size || (info.Mode().Perm()&0111 != 0) != expected.executable {
			return ErrInstallation
		}
		path := filepath.Join(root, name)
		file, err := os.Open(path)
		if err != nil {
			return ErrInstallation
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			file.Close()
			return ErrInstallation
		}
		hash := sha256.New()
		n, readErr := io.Copy(hash, contextReader{ctx, io.LimitReader(file, expected.size+1)})
		closeErr := file.Close()
		after, err := installedPath(ctx, root, name, owner, false)
		if readErr != nil || closeErr != nil || err != nil || !os.SameFile(info, after) || n != expected.size || [32]byte(hash.Sum(nil)) != expected.hash || ctx.Err() != nil {
			return ErrInstallation
		}
	}
	return nil
}
