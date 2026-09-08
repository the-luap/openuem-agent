package activatecommand

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

func privateDescriptor(directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	return windows.SecurityDescriptorFromString("O:BAD:P(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)")
}

func protectedObject(file *os.File, private bool) error {
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrAccess
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrAccess
	}
	defer runtime.KeepAlive(sd)
	trusted := func(sid *windows.SID) bool {
		return sid != nil && sid.IsValid() && (sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return ErrAccess
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount > 128 {
		return ErrAccess
	}
	const deleteChild = 0x0040 // FILE_DELETE_CHILD (directory access right).
	const writes = windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | deleteChild
	for i := uint16(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, uint32(i), &ace) != nil || ace == nil {
			return ErrAccess
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrAccess
		}
		if !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) && (private || ace.Mask&writes != 0) {
			return ErrAccess
		}
	}
	return nil
}

func openProtected(path string, directory, private bool) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if (directory && !before.IsDir()) || (!directory && !before.Mode().IsRegular()) {
		return nil, ErrAccess
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrAccess
	}
	flags, access, share := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT), uint32(windows.GENERIC_READ), uint32(windows.FILE_SHARE_READ)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		share |= windows.FILE_SHARE_WRITE
	}
	handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || protectedObject(file, private) != nil {
		_ = file.Close()
		return nil, ErrAccess
	}
	return file, nil
}

func ensurePrivateDirectory(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sd, err := privateDescriptor(true)
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(name, &attributes)
	runtime.KeepAlive(sd)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	return openProtected(path, true, true)
}

func readConfiguration(path string) ([]byte, error) {
	file, err := openProtected(path, false, true)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() < 1 || info.Size() > maxConfiguration {
		return nil, ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfiguration+1))
	if err != nil || len(data) > maxConfiguration {
		return nil, ErrConfiguration
	}
	return data, nil
}

func publishConfiguration(path string, data []byte) error {
	if len(data) == 0 || len(data) > maxConfiguration {
		return ErrConfiguration
	}
	parent, err := openProtected(filepath.Dir(path), true, true)
	if err != nil {
		return err
	}
	defer parent.Close()
	temporary := filepath.Join(filepath.Dir(path), ".activate-"+uuid.NewString()+".tmp")
	name, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	sd, err := privateDescriptor(false)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.GENERIC_READ, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), temporary)
	owned, _ := file.Stat()
	defer func() {
		_ = file.Close()
		if current, err := os.Lstat(temporary); err == nil && owned != nil && os.SameFile(owned, current) {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	destination, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(name, destination, windows.MOVEFILE_WRITE_THROUGH)
}
