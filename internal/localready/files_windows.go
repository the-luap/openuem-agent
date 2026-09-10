package localready

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

const pipeAddressFile = ".openuem-readiness.pipe"
const pipeAddressPrefix = "openuem-readiness-v1:"

func trustedWindowsSID(sid *windows.SID) bool {
	return sid != nil && sid.IsValid() && (sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

func privateWindowsHandle(handle windows.Handle, pipe bool, allowAdminServer bool) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrUnavailable
	}
	defer runtime.KeepAlive(sd)
	owner, _, err := sd.Owner()
	if err != nil || !trustedWindowsSID(owner) {
		return ErrConflict
	}
	if pipe && !allowAdminServer && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return ErrConflict
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount > 128 {
		return ErrConflict
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil {
			return ErrConflict
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrConflict
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask != 0 && !trustedWindowsSID(sid) {
			return ErrConflict
		}
		// FILE_APPEND_DATA is also FILE_CREATE_PIPE_INSTANCE. Administrators
		// may query the System service, but must not join its listener name.
		if pipe && !allowAdminServer && sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && uint32(ace.Mask) & ^uint32(pipeClientAccess) != 0 {
			return ErrConflict
		}
	}
	return nil
}

func openWindowsPrivate(path string, directory bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	flags, share := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT), uint32(windows.FILE_SHARE_READ)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		share |= windows.FILE_SHARE_WRITE
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	var info windows.ByHandleFileInformation
	stat, err := file.Stat()
	if err != nil || windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || stat.IsDir() != directory || (!directory && (!stat.Mode().IsRegular() || info.NumberOfLinks != 1)) || privateWindowsHandle(handle, false, false) != nil {
		file.Close()
		return nil, ErrConflict
	}
	return file, nil
}

func sameWindowsPath(file *os.File) bool {
	// Metadata-only access avoids conflicting with this reader's own sharing
	// protection. Compare kernel file IDs, never mutable path strings alone.
	name, err := windows.UTF16PtrFromString(file.Name())
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var opened, current windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &opened) == nil && windows.GetFileInformationByHandle(handle, &current) == nil && current.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 && opened.VolumeSerialNumber == current.VolumeSerialNumber && opened.FileIndexHigh == current.FileIndexHigh && opened.FileIndexLow == current.FileIndexLow && privateWindowsHandle(windows.Handle(file.Fd()), false, false) == nil
}

func windowsPipeAddress(directory string, create bool) (string, *os.File, error) {
	path := filepath.Join(directory, pipeAddressFile)
	file, err := openWindowsPrivate(path, false)
	if errors.Is(err, os.ErrNotExist) && create {
		name, nameErr := windows.UTF16PtrFromString(path)
		if nameErr != nil {
			return "", nil, ErrUnavailable
		}
		sd, sdErr := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
		if sdErr != nil {
			return "", nil, ErrUnavailable
		}
		attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		handle, createErr := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		runtime.KeepAlive(sd)
		if createErr == nil {
			writer := os.NewFile(uintptr(handle), path)
			data := []byte(pipeAddressPrefix + uuid.NewString())
			_, writeErr := writer.Write(data)
			syncErr := writer.Sync()
			closeErr := writer.Close()
			// Keep partial publication for inspection; never remove or overwrite
			// an address after an uncertain write or another process's win.
			if writeErr != nil || syncErr != nil || closeErr != nil {
				return "", nil, ErrUnavailable
			}
		} else if !errors.Is(createErr, os.ErrExist) {
			return "", nil, ErrUnavailable
		}
		file, err = openWindowsPrivate(path, false)
	}
	if err != nil {
		return "", nil, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, 128))
	value := strings.TrimPrefix(string(data), pipeAddressPrefix)
	id, parseErr := uuid.Parse(value)
	if err != nil || len(data) != len(pipeAddressPrefix)+36 || parseErr != nil || id.String() != value || !sameWindowsPath(file) {
		file.Close()
		return "", nil, ErrConflict
	}
	return `\\.\pipe\OpenUEM.Agent.Readiness.v1.` + value, file, nil
}
