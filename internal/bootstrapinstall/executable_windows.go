package bootstrapinstall

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openCodeFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrPackage
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, ErrPackage
	}
	return os.NewFile(uintptr(handle), path), nil
}

func codeFileProtected(file *os.File, _ os.FileInfo) error {
	security, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrPackage
	}
	defer runtime.KeepAlive(security)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ErrPackage
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && sid.IsValid() && (sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := security.Owner()
	if err != nil || !trusted(owner) {
		return ErrPackage
	}
	dacl, _, err := security.DACL()
	if err != nil || dacl == nil || dacl.AceCount > 128 {
		return ErrPackage
	}
	const writes = windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil || ace == nil {
			return ErrPackage
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrPackage
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask&writes != 0 && !trusted(sid) {
			return ErrPackage
		}
	}
	return nil
}
