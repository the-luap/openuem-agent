package packagesignature

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func verifyNative(ctx context.Context, path, format string) error {
	executable, err := os.Executable()
	if err != nil {
		return ErrUntrusted
	}
	command := exec.CommandContext(ctx, executable, helperArgument, path, format)
	// The same installed executable dispatches this read-only helper before any
	// logger, identity store or service startup. Killing the child bounds WinTrust.
	command.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	data, err := runCheck(ctx, command)
	defer clear(data)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, []byte("verified\n")) {
		return ErrUntrusted
	}
	return nil
}

// HandleHelper is called before service/logger initialization by the installed
// agent. It reads one local installer and performs Authenticode verification; it
// never launches the installer, changes trust stores or reads enrollment secrets.
// The parent Verify call bounds and joins this process. Nonmatching arguments
// leave ordinary service startup unchanged.
func HandleHelper(args []string) (bool, int) {
	if len(args) == 0 || args[0] != helperArgument {
		return false, 0
	}
	if len(args) != 3 || !validCandidate(args[1], args[2]) {
		return true, 1
	}
	if err := verifyWindowsFile(args[1]); err != nil {
		return true, 1
	}
	if _, err := os.Stdout.WriteString("verified\n"); err != nil {
		return true, 1
	}
	return true, 0
}

func verifyWindowsFile(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrUntrusted
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return ErrUntrusted
	}
	// Deny write/delete sharing throughout the policy check and pass the opened
	// descriptor to WinTrust. A substituted final reparse point is rejected.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return ErrUntrusted
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return ErrUntrusted
	}
	info := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: name, File: handle}
	data := windows.WinTrustData{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice: windows.WTD_UI_NONE, RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN,
		UnionChoice: windows.WTD_CHOICE_FILE, StateAction: windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&info),
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | windows.WTD_DISABLE_MD2_MD4 | windows.WTD_MOTW,
		UIContext:                       windows.WTD_UICONTEXT_INSTALL,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	runtime.KeepAlive(info)
	runtime.KeepAlive(name)
	runtime.KeepAlive(file)
	if verifyErr != nil || closeErr != nil {
		return ErrUntrusted
	}
	return nil
}
