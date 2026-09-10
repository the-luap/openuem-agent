package enrollmentstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/windows"
)

// AcquireServiceLease pins the existing protected directory and obtains an
// exclusive, non-inheritable file handle. Kernel sharing exclusion survives
// concurrent processes and ends on process exit; an existing lock is not reset.
func AcquireServiceLease(directory string) (*ServiceLease, error) {
	if !nativepath.Valid(directory) || checkSystemDirectory(directory) != nil {
		return nil, ErrUnavailable
	}
	rootName, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return nil, ErrUnavailable
	}
	root, err := windows.CreateFile(rootName, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	l := &ServiceLease{directory: directory, root: os.NewFile(uintptr(root), directory)}
	accepted := false
	defer func() {
		if !accepted {
			l.Close()
		}
	}()
	if systemOnly(l.root) != nil {
		return nil, ErrUnavailable
	}
	path := filepath.Join(directory, serviceLeaseName)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	descriptor, err := systemDescriptor(false)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer runtime.KeepAlive(descriptor)
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attributes, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrServiceBusy
		}
		return nil, ErrUnavailable
	}
	l.file = os.NewFile(uintptr(handle), path)
	if l.validateNative() != nil {
		return nil, ErrUnavailable
	}
	accepted = true
	return l, nil
}

func (l *ServiceLease) validateNative() error {
	root, err := l.root.Stat()
	if err != nil {
		return ErrUnavailable
	}
	file, err := l.file.Stat()
	if err != nil {
		return ErrUnavailable
	}
	currentRoot, err := serviceLeaseFileInfo(l.directory)
	if err != nil {
		return ErrUnavailable
	}
	currentFile, err := serviceLeaseFileInfo(filepath.Join(l.directory, serviceLeaseName))
	if err != nil {
		return ErrUnavailable
	}
	var rootInfo, fileInfo windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(l.root.Fd()), &rootInfo) != nil || windows.GetFileInformationByHandle(windows.Handle(l.file.Fd()), &fileInfo) != nil {
		return ErrUnavailable
	}
	if rootInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || fileInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || !root.IsDir() || !file.Mode().IsRegular() || file.Size() != 0 || fileInfo.NumberOfLinks != 1 || !os.SameFile(root, currentRoot) || !os.SameFile(file, currentFile) || systemOnly(l.root) != nil || systemOnly(l.file) != nil {
		return ErrUnavailable
	}
	return nil
}

// os.SameFile lazily opens path-based FileInfo with no sharing on Windows.
// That conflicts with our own exclusive data handle. A metadata-only handle
// requests no data access and permits the existing owner's read/write access;
// it cannot read, mutate or delete the lock, or admit another service owner.
func serviceLeaseFileInfo(path string) (os.FileInfo, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	handle, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	return file.Stat()
}
