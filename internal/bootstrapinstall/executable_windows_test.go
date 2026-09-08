package bootstrapinstall

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
	"golang.org/x/sys/windows"
)

func TestWindowsCodeAllowsPublicReadButRejectsUntrustedWriteAndReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.exe")
	if err := keyfile.Create(path, []byte("non-executable code permissions fixture")); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	setACL := func(access string) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")(A;;" + access + ";;;WD)")
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	setACL("GR")
	e, err := openAgentExecutable(path)
	if err != nil {
		t.Fatal("readable protected executable rejected", err)
	}
	defer e.Close()
	if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		file.Close()
		t.Fatal("open executable allowed concurrent writer")
	}
	if err := os.Rename(path, path+".moved"); err == nil {
		t.Fatal("open executable allowed replacement")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	setACL("GW")
	if e, err := openAgentExecutable(path); err == nil {
		e.Close()
		t.Fatal("untrusted code write access accepted")
	}
}
