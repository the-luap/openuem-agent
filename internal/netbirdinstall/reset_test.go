package netbirdinstall

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment/keyfile"
)

func abandonedPreparation(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix preparation")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "netbird-preparation")
	if err := keyfile.CreateDirectory(root); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "netbird-package-"+uuid.NewString())
	if err := keyfile.CreateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	return root, dir
}

func TestResetPreparationRootRemovesOnlyBoundedCrashArtifacts(t *testing.T) {
	for _, name := range []string{"", "package.deb", "package.rpm", "package.pkg"} {
		t.Run("partial-"+name, func(t *testing.T) {
			root, dir := abandonedPreparation(t)
			if name != "" {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("owned partial download"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if err := ResetRoot(root); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("abandoned preparation retained")
			}
		})
	}
}

func TestResetPreparationRootPreservesUnexpectedAndUnprotectedEntries(t *testing.T) {
	for _, kind := range []string{"root-entry", "multiple-stages", "extra-file", "nested-directory", "file-symlink", "stage-symlink", "root-symlink", "public-file", "public-stage", "public-root", "public-parent", "malformed-name"} {
		t.Run(kind, func(t *testing.T) {
			root, dir := abandonedPreparation(t)
			path := filepath.Join(dir, "package.deb")
			if err := os.WriteFile(path, []byte("owned incomplete package"), 0600); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("preserve outside"), 0600); err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "root-entry":
				must(os.WriteFile(filepath.Join(root, "unknown"), []byte("preserve"), 0600))
			case "multiple-stages":
				must(os.Mkdir(filepath.Join(root, "netbird-package-"+uuid.NewString()), 0700))
			case "extra-file":
				must(os.WriteFile(filepath.Join(dir, "unknown"), []byte("preserve"), 0600))
			case "nested-directory":
				must(os.Remove(path))
				must(os.Mkdir(path, 0700))
			case "file-symlink":
				must(os.Remove(path))
				must(os.Symlink(outside, path))
			case "stage-symlink":
				must(os.Rename(dir, dir+"-moved"))
				must(os.Symlink(dir+"-moved", dir))
			case "root-symlink":
				must(os.Rename(root, root+"-moved"))
				must(os.Symlink(root+"-moved", root))
			case "public-file":
				must(os.Chmod(path, 0644))
			case "public-stage":
				must(os.Chmod(dir, 0755))
			case "public-root":
				must(os.Chmod(root, 0755))
			case "public-parent":
				must(os.Chmod(filepath.Dir(root), 0755))
			case "malformed-name":
				must(os.Rename(dir, dir+"-unexpected"))
			}
			if err := ResetRoot(root); err == nil {
				t.Fatal("unsafe cleanup accepted")
			}
			if data, err := os.ReadFile(outside); err != nil || string(data) != "preserve outside" {
				t.Fatal("cleanup touched outside file")
			}
			if kind != "malformed-name" && kind != "nested-directory" {
				if _, err := os.Lstat(path); err != nil {
					t.Fatal("cleanup deleted an unexpected artifact", err)
				}
			}
		})
	}
}
