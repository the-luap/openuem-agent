//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNetbirdParentAllowsPublicReadButRejectsSharedWriteAndLinks(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "configuration")
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := checkNetbirdParent(parent); err != nil {
		t.Fatal("readable admin-owned configuration rejected", err)
	}
	for _, mode := range []os.FileMode{0775, 0777} {
		if err := os.Chmod(parent, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkNetbirdParent(parent); err == nil {
			t.Fatal("shared writable parent accepted")
		}
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(parent), "alias")
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	if err := checkNetbirdParent(link); err == nil {
		t.Fatal("symlink installation parent accepted")
	}
}
