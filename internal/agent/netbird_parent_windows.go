package agent

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func checkNetbirdParent(path string) error {
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return errNetbirdRuntime
	}
	f, err := os.Open(path)
	if err != nil {
		return errNetbirdRuntime
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return errNetbirdRuntime
	}
	security, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errNetbirdRuntime
	}
	defer runtime.KeepAlive(security)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errNetbirdRuntime
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && sid.IsValid() && (sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := security.Owner()
	if err != nil || !trusted(owner) {
		return errNetbirdRuntime
	}
	dacl, _, err := security.DACL()
	if err != nil || dacl == nil || dacl.AceCount > 128 {
		return errNetbirdRuntime
	}
	const deleteChild = 0x0040 // FILE_DELETE_CHILD is not exported by x/sys/windows.
	const mutation = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | deleteChild | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL
	for n := uint16(0); n < dacl.AceCount; n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(n), &ace) != nil || ace == nil {
			return errNetbirdRuntime
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errNetbirdRuntime
		}
		if ace.Mask&mutation != 0 && !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return errNetbirdRuntime
		}
	}
	return nil
}
