package linuxservice

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

var (
	fixtureConfiguration       = []byte("[Enrollment]\nDeviceID = owned-fixture\n[Agent]\nFrequency = 15\n")
	fixtureEditedConfiguration = []byte("[Enrollment]\nDeviceID = owned-fixture\n[Agent]\nFrequency = 20\n")
)

func configurationFixture(t *testing.T) (string, string, func([]byte) bool) {
	t.Helper()
	root := managerFixture(t)
	for _, name := range []string{"etc", "log"} {
		if err := os.Mkdir(filepath.Join(root, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(root, "etc", "openuem-agent"), filepath.Join(root, "log", "openuem-agent"), func(data []byte) bool {
		return bytes.Equal(data, fixtureConfiguration) || bytes.Equal(data, fixtureEditedConfiguration)
	}
}

func TestLinuxConfigurationPublishesAndPreservesMarkedSettings(t *testing.T) {
	config, logs, validate := configurationFixture(t)
	c, err := openConfigurationAt(t.Context(), config, logs, validate)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, name := range []string{config, logs} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("preflight created an operational directory", err)
		}
	}
	if err := c.Verify(t.Context()); !errors.Is(err, ErrConfiguration) {
		t.Fatal("absent configuration was ready", err)
	}
	if err := c.Prepare(t.Context(), fixtureConfiguration); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(config, configurationName)
	var first unix.Stat_t
	if unix.Lstat(filename, &first) != nil || !privateOperationalFile(first) {
		t.Fatal("published INI is not private")
	}
	if _, err := os.Lstat(filepath.Join(logs, logName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preparation created or truncated a log", err)
	}
	if err := os.WriteFile(filename, fixtureEditedConfiguration, 0600); err != nil {
		t.Fatal(err)
	}
	logData := []byte("owned preexisting log evidence")
	if err := os.WriteFile(filepath.Join(logs, logName), logData, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Prepare(t.Context(), fixtureConfiguration); err != nil {
		t.Fatal("valid administrator settings were not admitted", err)
	}
	if err := c.Verify(t.Context()); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if c.Verify(t.Context()) == nil || c.Prepare(t.Context(), fixtureConfiguration) == nil {
		t.Fatal("closed configuration owner remained usable")
	}
	c, err = openConfigurationAt(t.Context(), config, logs, validate)
	if err != nil {
		t.Fatal("retained configuration could not be reopened", err)
	}
	defer c.Close()
	if err := c.Prepare(t.Context(), fixtureConfiguration); err != nil {
		t.Fatal(err)
	}
	var after unix.Stat_t
	data, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(data, fixtureEditedConfiguration) || unix.Lstat(filename, &after) != nil || first.Dev != after.Dev || first.Ino != after.Ino {
		t.Fatal("retry rewrote the admitted configuration", err)
	}
	if data, err := os.ReadFile(filepath.Join(logs, logName)); err != nil || !bytes.Equal(data, logData) {
		t.Fatal("preparation changed log evidence", err)
	}
	entries, err := os.ReadDir(config)
	if err != nil || len(entries) != 1 || entries[0].Name() != configurationName {
		t.Fatal("temporary publication files survived", err)
	}
}

func TestLinuxConfigurationRejectsForeignFilesAndNamespaces(t *testing.T) {
	for _, scenario := range []string{"legacy", "other-identity", "empty", "oversized", "symlink", "hardlink", "fifo", "directory", "foreign-owner", "public-file", "executable-file", "special-file", "public-directory", "foreign-directory", "symlink-directory", "parent-writable", "parent-symlink", "log-without-config", "log-symlink", "log-hardlink", "log-fifo", "log-public", "log-foreign", "log-directory"} {
		t.Run(scenario, func(t *testing.T) {
			config, logs, validate := configurationFixture(t)
			if os.Mkdir(config, 0700) != nil || os.Mkdir(logs, 0700) != nil {
				t.Fatal("could not create private fixture")
			}
			filename, log := filepath.Join(config, configurationName), filepath.Join(logs, logName)
			data := bytes.Clone(fixtureConfiguration)
			switch scenario {
			case "legacy":
				data = []byte("[Agent]\nLegacy = true\n")
			case "other-identity":
				data = bytes.ReplaceAll(data, []byte("owned-fixture"), []byte("another-fixture"))
			case "empty":
				data = nil
			case "oversized":
				data = bytes.Repeat([]byte("x"), maxOperationalConfiguration+1)
			}
			if err := os.WriteFile(filename, data, 0600); err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "symlink":
				must(os.Remove(filename))
				must(os.Symlink("/owned-unrelated", filename))
			case "hardlink":
				must(os.Link(filename, filename+".link"))
			case "fifo":
				must(os.Remove(filename))
				must(unix.Mkfifo(filename, 0600))
			case "directory":
				must(os.Remove(filename))
				must(os.Mkdir(filename, 0700))
			case "foreign-owner":
				must(os.Chown(filename, 65534, 65534))
			case "public-file":
				must(os.Chmod(filename, 0644))
			case "executable-file":
				must(os.Chmod(filename, 0700))
			case "special-file":
				must(os.Chmod(filename, 0600|os.ModeSetuid))
			case "public-directory":
				must(os.Chmod(config, 0755))
			case "foreign-directory":
				must(os.Chown(config, 65534, 65534))
			case "symlink-directory":
				must(os.Rename(config, config+".held"))
				must(os.Symlink(config+".held", config))
			case "parent-writable":
				must(os.Chmod(filepath.Dir(config), 0777))
			case "parent-symlink":
				must(os.Rename(filepath.Dir(config), filepath.Dir(config)+".held"))
				must(os.Symlink(filepath.Dir(config)+".held", filepath.Dir(config)))
			}
			if strings.HasPrefix(scenario, "log-") {
				must(os.WriteFile(log, []byte("owned retained log"), 0600))
				switch scenario {
				case "log-without-config":
					must(os.Remove(filename))
				case "log-symlink":
					must(os.Remove(log))
					must(os.Symlink("/owned-unrelated", log))
				case "log-hardlink":
					must(os.Link(log, log+".link"))
				case "log-fifo":
					must(os.Remove(log))
					must(unix.Mkfifo(log, 0600))
				case "log-public":
					must(os.Chmod(log, 0644))
				case "log-foreign":
					must(os.Chown(log, 65534, 65534))
				case "log-directory":
					must(os.Remove(log))
					must(os.Mkdir(log, 0700))
				}
			}
			c, err := openConfigurationAt(t.Context(), config, logs, validate)
			if c != nil {
				c.Close()
			}
			if !errors.Is(err, ErrConfiguration) {
				t.Fatal("foreign operational namespace was admitted", err)
			}
		})
	}
}

func TestLinuxConfigurationRetainsReplacementsAndCancellation(t *testing.T) {
	for _, scenario := range []string{"canceled", "invalid-input", "changed-file", "changed-config-directory", "changed-log-directory", "changed-parent", "foreign-log"} {
		t.Run(scenario, func(t *testing.T) {
			config, logs, validate := configurationFixture(t)
			c, err := openConfigurationAt(t.Context(), config, logs, validate)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if scenario == "canceled" || scenario == "invalid-input" {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				data := fixtureConfiguration
				if scenario == "canceled" {
					cancel()
				} else {
					data = []byte("owned invalid input")
				}
				if c.Prepare(ctx, data) == nil {
					t.Fatal("invalid or canceled input published")
				}
				for _, name := range []string{config, logs} {
					if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("rejected input created a directory")
					}
				}
				return
			}
			if err := c.Prepare(t.Context(), fixtureConfiguration); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(config, configurationName)
			var foreign string
			switch scenario {
			case "changed-file":
				foreign = filename
			case "changed-config-directory":
				foreign = config
			case "changed-log-directory":
				foreign = logs
			case "changed-parent":
				foreign = filepath.Dir(config)
			case "foreign-log":
				if err := os.Symlink("/owned-unrelated", filepath.Join(logs, logName)); err != nil {
					t.Fatal(err)
				}
			}
			if foreign != "" {
				if err := os.Rename(foreign, foreign+".held"); err != nil {
					t.Fatal(err)
				}
				if foreign == filename {
					if err := os.WriteFile(filename, fixtureConfiguration, 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Mkdir(foreign, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if c.Verify(t.Context()) == nil || c.Prepare(t.Context(), fixtureConfiguration) == nil {
				t.Fatal("changed retained namespace was admitted")
			}
			c.Close()
			if foreign != "" {
				if _, err := os.Lstat(foreign); err != nil {
					t.Fatal("close removed a replacement", err)
				}
			}
		})
	}
}

func TestLinuxConfigurationConcurrentExclusivePublication(t *testing.T) {
	config, logs, validate := configurationFixture(t)
	var workers sync.WaitGroup
	for range 12 {
		workers.Go(func() {
			c, err := openConfigurationAt(t.Context(), config, logs, validate)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			if err := c.Prepare(t.Context(), fixtureConfiguration); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if data, err := os.ReadFile(filepath.Join(config, configurationName)); err != nil || !bytes.Equal(data, fixtureConfiguration) {
		t.Fatal("concurrent publication lost the complete configuration", err)
	}
	entries, err := os.ReadDir(config)
	if err != nil || len(entries) != 1 || entries[0].Name() != configurationName {
		t.Fatal("concurrent publication retained temporary files", err)
	}
}
