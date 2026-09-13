//go:build linux || darwin

package netbirdjournal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalRejectsSharedFilesSymlinksHardlinksAndReplacement(t *testing.T) {
	for _, kind := range []string{"directory", "record", "symlink", "hardlink", "replacement"} {
		t.Run(kind, func(t *testing.T) {
			c := testCommand()
			path := filepath.Join(t.TempDir(), "journal")
			j := openTest(t, path, c, testBoot())
			beginTest(t, j, c)
			if kind == "replacement" {
				if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if _, err := j.Lookup(c); !errors.Is(err, ErrUnavailable) {
					t.Fatal("replaced directory remained trusted", err)
				}
				return
			}
			j.Close()
			record := filepath.Join(path, "0001-start.json")
			switch kind {
			case "directory":
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "record":
				if err := os.Chmod(record, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(record, record+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(record+"-old", record); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(record, filepath.Join(filepath.Dir(path), "external-link")); err != nil {
					t.Fatal(err)
				}
			}
			if restored, err := Open(path, strings.Repeat("b", 64), c.Identity, testBoot()); err == nil {
				restored.Close()
				t.Fatal("unsafe journal reopened")
			}
		})
	}
}
