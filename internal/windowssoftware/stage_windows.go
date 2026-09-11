//go:build windows

package windowssoftware

import (
	"os"

	"github.com/open-uem/nats/enrollment/keyfile"
	"golang.org/x/sys/windows"
)

func openStagedArtifact(path string, size int64) (*os.File, error) {
	checked, err := keyfile.Open(path, size)
	if err != nil {
		return nil, ErrArtifactChanged
	}
	info, err := checked.Stat()
	closeErr := checked.Close()
	if err != nil || closeErr != nil {
		return nil, ErrArtifactChanged
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrArtifactChanged
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, ErrArtifactChanged
	}
	file := os.NewFile(uintptr(handle), path)
	var native windows.ByHandleFileInformation
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) || windows.GetFileInformationByHandle(handle, &native) != nil || native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || native.NumberOfLinks != 1 {
		file.Close()
		return nil, ErrArtifactChanged
	}
	return file, nil
}
