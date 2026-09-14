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

func unitFileFixture(t *testing.T) (string, Spec, []byte) {
	t.Helper()
	root := managerFixture(t)
	directory := filepath.Join(root, "system")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	spec := Spec{Executable: "/opt/openuem/agent", IdentityDirectory: "/var/lib/openuem/identity"}
	data, err := Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, UnitName), spec, data
}

func TestLinuxUnitFilePublicationAndRetainedRetry(t *testing.T) {
	filename, spec, expected := unitFileFixture(t)
	u, err := openUnitFileAt(filename, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if present, err := u.inspect(); err != nil || present {
		t.Fatal("missing unit was not observed", present, err)
	}
	if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection created a unit", err)
	}
	if err := u.publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	var initial unix.Stat_t
	if unix.Lstat(filename, &initial) != nil || !unitMetadata(initial) || initial.Mode&07777 != 0644 {
		t.Fatal("published unit metadata is unsafe")
	}
	data, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(data, expected) {
		t.Fatal("published definition differs", err)
	}
	for range 2 {
		if err := u.publish(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	u.Close()
	if _, err := u.inspect(); !errors.Is(err, ErrUnit) {
		t.Fatal("closed owner inspected a unit", err)
	}
	if err := u.publish(context.Background()); !errors.Is(err, ErrUnit) {
		t.Fatal("closed owner published", err)
	}
	u, err = openUnitFileAt(filename, spec)
	if err != nil {
		t.Fatal("retry lost retained unit", err)
	}
	defer u.Close()
	if err := u.publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	var current unix.Stat_t
	if unix.Lstat(filename, &current) != nil || !sameStamp(initial, current) {
		t.Fatal("retry rewrote existing unit")
	}
	entries, err := os.ReadDir(filepath.Dir(filename))
	if err != nil || len(entries) != 1 || entries[0].Name() != UnitName {
		t.Fatal("publication retained temporary files", entries, err)
	}
}

func TestLinuxUnitFileRejectsForeignDefinitionsAndMetadata(t *testing.T) {
	for _, scenario := range []string{"content", "extra-command", "other-identity", "empty", "oversized", "foreign-owner", "writable", "executable", "special-mode", "hardlink", "symlink", "directory", "fifo", "parent-symlink", "parent-writable"} {
		t.Run(scenario, func(t *testing.T) {
			filename, spec, data := unitFileFixture(t)
			switch scenario {
			case "content":
				data = []byte("[Service]\nExecStart=/unapproved/service\n")
			case "extra-command":
				data = append(data, []byte("ExecStartPre=/unapproved/hook\n")...)
			case "other-identity":
				other := spec
				other.IdentityDirectory += "-other"
				data, _ = Render(other)
			case "empty":
				data = nil
			case "oversized":
				data = bytes.Repeat([]byte("x"), MaxUnitSize+1)
			}
			if err := os.WriteFile(filename, data, 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "foreign-owner":
				if err := os.Chown(filename, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(filename, 0666); err != nil {
					t.Fatal(err)
				}
			case "executable":
				if err := os.Chmod(filename, 0700); err != nil {
					t.Fatal(err)
				}
			case "special-mode":
				if err := unix.Chmod(filename, 04600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filename, filename+"-alias"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(filename, filename+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filename+"-retained", filename); err != nil {
					t.Fatal(err)
				}
			case "directory", "fifo":
				if err := os.Remove(filename); err != nil {
					t.Fatal(err)
				}
				if scenario == "directory" {
					if err := os.Mkdir(filename, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := unix.Mkfifo(filename, 0600); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				dir := filepath.Dir(filename)
				if err := os.Rename(dir, dir+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+"-retained", dir); err != nil {
					t.Fatal(err)
				}
			case "parent-writable":
				if err := os.Chmod(filepath.Dir(filename), 0777); err != nil {
					t.Fatal(err)
				}
			}
			var before, after unix.Stat_t
			if unix.Lstat(filename, &before) != nil {
				t.Fatal("fixture lost original")
			}
			u, err := openUnitFileAt(filename, spec)
			if u != nil {
				u.Close()
			}
			if !errors.Is(err, ErrUnit) {
				t.Fatal("foreign definition admitted", err)
			}
			if unix.Lstat(filename, &after) != nil || !sameStamp(before, after) {
				t.Fatal("inspection changed foreign object")
			}
		})
	}
}

func TestLinuxUnitFilePreservesChangedNamespaceAndCancellation(t *testing.T) {
	for _, scenario := range []string{"replace-unit", "change-mode", "change-bytes", "hardlink", "replace-parent", "writable-parent", "foreign-arrival", "cancel-before", "cancel-after"} {
		t.Run(scenario, func(t *testing.T) {
			filename, spec, expected := unitFileFixture(t)
			u, err := openUnitFileAt(filename, spec)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			missing := scenario == "cancel-before" || scenario == "foreign-arrival"
			if !missing {
				if err := u.publish(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "replace-unit":
				if err := os.Rename(filename, filename+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filename, expected, 0644); err != nil {
					t.Fatal(err)
				}
			case "change-mode":
				if err := os.Chmod(filename, 0666); err != nil {
					t.Fatal(err)
				}
			case "change-bytes":
				if err := os.WriteFile(filename, []byte("foreign unit"), 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filename, filename+"-alias"); err != nil {
					t.Fatal(err)
				}
			case "replace-parent":
				dir := filepath.Dir(filename)
				if err := os.Rename(dir, dir+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filename, expected, 0644); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := os.Chmod(filepath.Dir(filename), 0777); err != nil {
					t.Fatal(err)
				}
			case "foreign-arrival":
				if err := os.WriteFile(filename, []byte("arrived foreign unit"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var before, after unix.Stat_t
			beforeErr := unix.Lstat(filename, &before)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if strings.HasPrefix(scenario, "cancel-") {
				cancel()
			}
			err = u.publish(ctx)
			wantErr := ErrUnit
			if strings.HasPrefix(scenario, "cancel-") {
				wantErr = context.Canceled
			}
			if !errors.Is(err, wantErr) {
				t.Fatal("changed/canceled publication admitted", err)
			}
			u.Close()
			if scenario == "cancel-before" {
				entries, err := os.ReadDir(filepath.Dir(filename))
				if err != nil || len(entries) != 0 {
					t.Fatal("canceled operation created entries", entries, err)
				}
			} else if beforeErr != nil || unix.Lstat(filename, &after) != nil || !sameStamp(before, after) {
				t.Fatal("publication or close modified retained object")
			}
		})
	}
}

func TestLinuxUnitFileConcurrentExclusivePublication(t *testing.T) {
	filename, spec, expected := unitFileFixture(t)
	const writers = 12
	owners := make([]*unitFile, writers)
	for i := range owners {
		var err error
		owners[i], err = openUnitFileAt(filename, spec)
		if err != nil {
			t.Fatal(err)
		}
		defer owners[i].Close()
	}
	start := make(chan struct{})
	results := make(chan error, writers)
	var wg sync.WaitGroup
	for _, owner := range owners {
		wg.Go(func() { <-start; results <- owner.publish(context.Background()) })
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("exact concurrent publisher failed", err)
		}
	}
	var published unix.Stat_t
	if unix.Lstat(filename, &published) != nil {
		t.Fatal("winner absent")
	}
	for _, owner := range owners {
		if !sameStamp(owner.stamp, published) {
			t.Fatal("writers retained different definitions")
		}
		if present, err := owner.inspect(); err != nil || !present {
			t.Fatal("concurrent publication was incomplete", err)
		}
	}
	data, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(data, expected) {
		t.Fatal("winner not canonical", err)
	}
	entries, err := os.ReadDir(filepath.Dir(filename))
	if err != nil || len(entries) != 1 {
		t.Fatal("losing publishers retained temporary objects", entries, err)
	}
}
