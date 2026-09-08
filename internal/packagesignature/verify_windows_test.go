package packagesignature

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsAuthenticodeAcceptsSystemSignedBytesAndRejectsMutation(t *testing.T) {
	// Copy a Microsoft-signed OS executable only as signature-verification data;
	// it is never executed. No certificate is imported into the test machine.
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateTestDirectory(t), "signed-fixture.exe")
	copySignatureFixture(t, filepath.Join(directory, "WindowsPowerShell", "v1.0", "powershell.exe"), path)
	if err := Verify(context.Background(), path, "exe"); err != nil {
		t.Fatal("Microsoft-signed fixture was not accepted", err)
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
