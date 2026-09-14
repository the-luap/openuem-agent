package linuxservice

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func enablementFixture(t *testing.T) (string, string) {
	t.Helper()
	filename, _, _ := unitFileFixture(t)
	parent := filepath.Dir(filename)
	return parent, filepath.Join(parent, wantsDirectory, UnitName)
}

func createEnablementFixture(t *testing.T, link string) {
	t.Helper()
	if err := os.Mkdir(filepath.Dir(link), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(UnitPath, link); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxEnablementRetainsCanonicalLinkWithoutMutation(t *testing.T) {
	parent, link := enablementFixture(t)
	e, err := openUnitEnablementAt(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if enabled, err := e.inspect(); err != nil || enabled {
		t.Fatal("absent link was not observed", enabled, err)
	}
	if err := e.flush(context.Background()); !errors.Is(err, ErrUnit) {
		t.Fatal("absent enablement was flushed", err)
	}
	if _, err := os.Lstat(filepath.Dir(link)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("observation created a wants directory", err)
	}
	if err := os.Mkdir(filepath.Dir(link), 0755); err != nil {
		t.Fatal(err)
	}
	if enabled, err := e.inspect(); err != nil || enabled {
		t.Fatal("empty wants directory was not admitted", enabled, err)
	}
	if err := os.Symlink(UnitPath, link); err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if unix.Lstat(link, &before) != nil {
		t.Fatal("link fixture unavailable")
	}
	for range 2 {
		if enabled, err := e.inspect(); err != nil || !enabled {
			t.Fatal("canonical link was not admitted", enabled, err)
		}
		if err := e.flush(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.flush(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled flush was admitted", err)
	}
	e.Close()
	if enabled, err := e.inspect(); !errors.Is(err, ErrUnit) || enabled {
		t.Fatal("closed owner inspected enablement", enabled, err)
	}
	if err := e.flush(context.Background()); !errors.Is(err, ErrUnit) {
		t.Fatal("closed owner flushed enablement", err)
	}
	retry, err := openUnitEnablementAt(parent)
	if err != nil {
		t.Fatal("retained enablement could not be reopened", err)
	}
	retry.Close()
	var after unix.Stat_t
	if unix.Lstat(link, &after) != nil || !sameStamp(before, after) {
		t.Fatal("inspection, flush or close modified the symlink")
	}
}

func TestLinuxEnablementRejectsForeignLinksAndParents(t *testing.T) {
	for _, scenario := range []string{"relative", "foreign-target", "longer-target", "hardlink", "foreign-owner", "regular", "directory", "fifo", "wants-alias", "wants-writable", "wants-owner", "wants-special", "parent-alias", "parent-writable"} {
		t.Run(scenario, func(t *testing.T) {
			parent, link := enablementFixture(t)
			createEnablementFixture(t, link)
			var err error
			switch scenario {
			case "relative", "foreign-target", "longer-target", "regular", "directory", "fifo":
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "relative":
					err = os.Symlink("../"+UnitName, link)
				case "foreign-target":
					err = os.Symlink("/usr/lib/systemd/system/"+UnitName, link)
				case "longer-target":
					err = os.Symlink(UnitPath+"-foreign", link)
				case "regular":
					err = os.WriteFile(link, []byte(UnitPath), 0644)
				case "directory":
					err = os.Mkdir(link, 0755)
				case "fifo":
					err = unix.Mkfifo(link, 0600)
				}
			case "hardlink":
				err = os.Link(link, link+"-other")
			case "foreign-owner":
				err = os.Lchown(link, 65534, 65534)
			case "wants-writable":
				err = os.Chmod(filepath.Dir(link), 0777)
			case "wants-owner":
				err = os.Chown(filepath.Dir(link), 65534, 65534)
			case "wants-special":
				err = unix.Chmod(filepath.Dir(link), 02755)
			case "parent-writable":
				err = os.Chmod(parent, 0777)
			case "wants-alias", "parent-alias":
				entry := filepath.Dir(link)
				if scenario == "parent-alias" {
					entry = parent
				}
				if err := os.Rename(entry, entry+"-retained"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(entry+"-retained", entry)
			}
			if err != nil {
				t.Fatal("invalid fixture construction", err)
			}
			if e, err := openUnitEnablementAt(parent); !errors.Is(err, ErrUnit) {
				if e != nil {
					e.Close()
				}
				t.Fatal("foreign enablement was admitted", err)
			}
		})
	}
}

func TestLinuxEnablementRejectsReplacementsAndJoinsClose(t *testing.T) {
	for _, scenario := range []string{"link", "unlink", "wants", "parent", "permissions", "owner"} {
		t.Run(scenario, func(t *testing.T) {
			parent, link := enablementFixture(t)
			createEnablementFixture(t, link)
			e, err := openUnitEnablementAt(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			switch scenario {
			case "link", "unlink":
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				if scenario == "link" {
					if err := os.Symlink(UnitPath, link); err != nil {
						t.Fatal(err)
					}
				}
			case "wants", "parent":
				entry := filepath.Dir(link)
				if scenario == "parent" {
					entry = parent
				}
				if err := os.Rename(entry, entry+"-retained"); err != nil {
					t.Fatal(err)
				}
				if scenario == "parent" {
					if err := os.Mkdir(parent, 0755); err != nil {
						t.Fatal(err)
					}
				}
				createEnablementFixture(t, link)
			case "permissions":
				if err := os.Chmod(filepath.Dir(link), 0777); err != nil {
					t.Fatal(err)
				}
			case "owner":
				if err := os.Lchown(link, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			}
			if enabled, err := e.inspect(); !errors.Is(err, ErrUnit) || enabled {
				t.Fatal("replaced namespace remained admitted", enabled, err)
			}
			if err := e.flush(context.Background()); !errors.Is(err, ErrUnit) {
				t.Fatal("replaced namespace was flushed", err)
			}
			var workers sync.WaitGroup
			for range 8 {
				workers.Go(func() { e.inspect(); e.Close() })
			}
			workers.Wait()
			_, err = os.Lstat(link)
			if (scenario == "unlink" && !errors.Is(err, os.ErrNotExist)) || (scenario != "unlink" && err != nil) {
				t.Fatal("close changed the current namespace", err)
			}
		})
	}
}
