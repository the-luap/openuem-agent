//go:build windows

package runtime

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func NewCommandSession(ctx context.Context) (*CommandSession, error) {
	if ctx == nil {
		return nil, errors.New("command context required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var selected uint32
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "explorer.exe") {
			if selected != 0 {
				return nil, errors.New("command session is ambiguous")
			}
			selected = entry.ProcessID
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	var token syscall.Token
	var userEnv []string
	if selected != 0 {
		process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, selected)
		if err != nil {
			return nil, err
		}
		defer windows.CloseHandle(process)
		var nativeToken windows.Token
		if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY, &nativeToken); err != nil {
			return nil, err
		}
		token = syscall.Token(nativeToken)
		userEnv, err = nativeToken.Environ(false)
		if err != nil {
			nativeToken.Close()
			return nil, err
		}
	}
	session := &CommandSession{baseEnv: userEnv, prepare: func(cmd *exec.Cmd) {
		cmd.SysProcAttr = &syscall.SysProcAttr{Token: token, CreationFlags: windows.CREATE_NO_WINDOW}
	}}
	if token != 0 {
		session.close = token.Close
	}
	return session, nil
}
