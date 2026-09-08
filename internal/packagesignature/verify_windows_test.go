package packagesignature

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsAuthenticodeAcceptsEmbeddedSignatureAndRejectsMutation(t *testing.T) {
	// The Go project's existing EV-signed fixture has an embedded signature;
	// unlike a catalog-signed Windows system file it is independently verifiable
	// after copying. It is never executed and no certificate is imported.
	path := filepath.Join(privateTestDirectory(t), "signed-fixture.exe")
	copySignatureFixture(t, filepath.Join("testdata", "ev-signed-file.exe"), path)
	if !validCandidate(path, "exe") {
		t.Fatal("signature fixture did not meet private staging requirements")
	}
	if err := Verify(context.Background(), path, "exe"); err != nil {
		t.Fatal("embedded-signature fixture was not accepted", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the image's DOS header, which is covered by Authenticode.
	_, err = file.WriteAt([]byte{'X'}, 0)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), path, "exe"); !errors.Is(err, ErrUntrusted) {
		t.Fatal("changed signed fixture accepted", err)
	}
}
