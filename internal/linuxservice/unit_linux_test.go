package linuxservice

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxUnitAcceptedByNativeSystemdParser(t *testing.T) {
	if os.Getenv("OPENUEM_TEST_LINUX_UNITS") != "owned-isolated-units" {
		t.Skip("requires isolated native systemd unit fixture")
	}
	var fs unix.Statfs_t
	if os.Geteuid() != 0 || os.TempDir() != "/fixture" || unix.Statfs("/fixture", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Fatal("native unit fixture requires owned private tmpfs")
	}
	for _, scenario := range []string{"ordinary", "literal-paths", "missing-executable", "foreign-command"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			unitDirectory := filepath.Join(root, "etc/systemd/system")
			if err := os.MkdirAll(unitDirectory, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"sysinit.target", "basic.target", "shutdown.target", "network-online.target", "multi-user.target"} {
				if err := os.WriteFile(filepath.Join(unitDirectory, name), []byte("[Unit]\nDescription=Owned inert target\nDefaultDependencies=no\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			s := Spec{Executable: "/usr/bin/openuem-test", IdentityDirectory: "/var/lib/openuem-agent/identity"}
			if scenario == "literal-paths" {
				s.Executable = `/opt/OpenUEM agent/agent%u`
				s.IdentityDirectory = `/var/lib/OpenUEM $HOME/${USER}/"quoted"\identity%h`
			}
			image, err := os.ReadFile("/usr/bin/true")
			if err != nil {
				t.Fatal(err)
			}
			if err = os.MkdirAll(filepath.Dir(filepath.Join(root, s.Executable)), 0700); err != nil {
				t.Fatal(err)
			}
			if scenario != "missing-executable" {
				if err = os.WriteFile(filepath.Join(root, s.Executable), image, 0700); err != nil {
					t.Fatal(err)
				}
			}
			data, err := Render(s)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "foreign-command" {
				data = append(data, []byte("\n[Service]\nExecStartPre=/unapproved/must-not-execute\n")...)
			}
			if err = os.WriteFile(filepath.Join(root, UnitPath), data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/bin/systemd-analyze", "--root="+root, "--man=no", "--generators=no", "verify", filepath.Join(root, UnitPath))
			cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_LOG_LEVEL=debug", "SYSTEMD_LOG_TARGET=console", "TMPDIR=/fixture"}
			output, err := cmd.CombinedOutput()
			if len(output) > 1<<20 {
				t.Fatal("unexpectedly large native unit diagnostics")
			}
			if scenario == "missing-executable" || scenario == "foreign-command" {
				if err == nil || !bytes.Contains(output, []byte("is not executable")) {
					t.Fatalf("native parser did not reject the non-executable command: %v\n%s", err, output)
				}
				return
			}
			if err != nil {
				t.Fatalf("native systemd rejected unit: %v\n%s", err, output)
			}
			if !bytes.Contains(output, []byte("Type: exec")) || !bytes.Contains(output, []byte("User: root")) || !bytes.Contains(output, []byte("serve -identity-directory")) {
				t.Fatalf("native unit dump lost installed service contract:\n%s", output)
			}
			if scenario == "literal-paths" && (!bytes.Contains(output, []byte("identity%h")) || bytes.Contains(output, []byte("identity%%h")) || !bytes.Contains(output, []byte("${USER}"))) {
				t.Fatalf("native parser changed literal identity arguments:\n%s", output)
			}
			// Print only the owned parser's decoded argv, never a host unit dump.
			for _, line := range strings.Split(string(output), "\n") {
				if strings.Contains(line, "Command Line:") {
					t.Log(strings.TrimSpace(line))
				}
			}
		})
	}
}
