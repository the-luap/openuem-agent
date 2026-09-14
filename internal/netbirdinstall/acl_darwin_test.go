//go:build darwin && cgo

package netbirdinstall

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeInstallationACLRejectsWriteGrantsWithoutChangingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned-file")
	if err := os.WriteFile(path, []byte("owned"), 0600); err != nil {
		t.Fatal(err)
	}
	if !trustedNativeACL(path) {
		t.Fatal("empty native ACL rejected")
	}
	for _, grant := range []string{"everyone deny delete", "everyone allow read", "everyone allow write", "everyone allow writeattr", "everyone allow writesecurity"} {
		if err := exec.Command("/bin/chmod", "-N", path).Run(); err != nil {
			t.Fatal(err)
		}
		if err := exec.Command("/bin/chmod", "+a", grant, path).Run(); err != nil {
			t.Fatal(err)
		}
		want := grant == "everyone deny delete" || grant == "everyone allow read"
		if trustedNativeACL(path) != want {
			t.Fatal("native ACL grant classification failed", grant)
		}
		if (installationSourcePath(t.Context(), path, uint32(os.Geteuid())) == nil) != want {
			t.Fatal("private package source ignored its native ACL", grant)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("ACL inspection repaired permissions")
		}
	}
}

func TestNativeRemovalACLIsBoundToTheOwnedSnapshot(t *testing.T) {
	f := newRemovalFilesFixture(t)
	first, err := f.inspect(t.Context())
	f.must(err)
	path := filepath.Join(f.root, removalApp+"/Contents/Resources/LICENSE")
	f.must(exec.Command("/bin/chmod", "+a", "everyone allow read", path).Run())
	readable, err := f.inspect(t.Context())
	f.must(err)
	if readable.digest == first.digest || readable.objects[removalApp+"/Contents/Resources/LICENSE"].ACL == first.objects[removalApp+"/Contents/Resources/LICENSE"].ACL {
		t.Fatal("native ACL change was omitted from the ownership fingerprint")
	}
	f.must(exec.Command("/bin/chmod", "+a", "everyone allow write", path).Run())
	if result, err := f.inspect(t.Context()); err != errRemovalFiles || result != nil {
		t.Fatal("native ACL write grant admitted removal ownership", err)
	}
}
