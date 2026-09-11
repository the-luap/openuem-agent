//go:build windows

package deploy

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runWinGetProcess assigns a suspended child to a kill-on-close job before its
// first instruction. Cancellation owns this job, never a name-based task kill.
// Work delegated to independent Windows services can still outlive the command;
// interruption therefore cannot establish the installed state or a rollback.
func runWinGetProcess(ctx context.Context, executable string, args []string) (result winGetProcessResult, resultErr error) {
	return runWindowsProcess(ctx, executable, windows.ComposeCommandLine(append([]string{executable}, args...)))
}

// Command construction remains in the adapter: MSI has property-value quoting
// rules in addition to Windows argv rules. Ownership and cancellation are shared.
func runWindowsProcess(ctx context.Context, executable, commandLine string) (result winGetProcessResult, resultErr error) {
	if ctx == nil {
		return result, errors.New("execution context required")
	}
	if !filepath.IsAbs(executable) || !strings.EqualFold(filepath.Ext(executable), ".exe") {
		return result, errors.New("absolute executable required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	application, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return result, err
	}
	command, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return result, err
	}
	directory, err := windows.UTF16PtrFromString(filepath.Dir(executable))
	if err != nil {
		return result, err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return result, err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return result, err
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer outRead.Close()
	defer outWrite.Close()
	errRead, errWrite, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer errRead.Close()
	defer errWrite.Close()
	input, err := os.Open(os.DevNull)
	if err != nil {
		return result, err
	}
	defer input.Close()
	handles := []windows.Handle{windows.Handle(input.Fd()), windows.Handle(outWrite.Fd()), windows.Handle(errWrite.Fd())}
	for _, handle := range handles {
		if err = windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return result, err
		}
	}
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return result, err
	}
	defer attributes.Delete()
	if err = attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return result, err
	}
	startup := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2]}, ProcThreadAttributeList: attributes.List()}
	var process windows.ProcessInformation
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT | windows.IDLE_PRIORITY_CLASS)
	if err = windows.CreateProcess(application, command, nil, nil, true, flags, nil, directory, &startup.StartupInfo, &process); err != nil {
		return result, err
	}
	closeProcess := func() {
		if process.Process != 0 {
			_ = windows.CloseHandle(process.Process)
			process.Process = 0
		}
		if process.Thread != 0 {
			_ = windows.CloseHandle(process.Thread)
			process.Thread = 0
		}
	}
	defer closeProcess()
	if err = windows.AssignProcessToJobObject(job, process.Process); err != nil {
		_ = windows.TerminateProcess(process.Process, 1)
		_, _ = windows.WaitForSingleObject(process.Process, 2000)
		return result, err
	}
	var stdout, stderr boundedWinGetOutput
	var outErr, errErr error
	outDone, errDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(outDone); _, outErr = io.Copy(&stdout, outRead) }()
	go func() { defer close(errDone); _, errErr = io.Copy(&stderr, errRead) }()
	defer func() {
		// Terminate before releasing pipe readers, including partial startup.
		terminateErr := windows.TerminateJobObject(job, 1)
		closeProcess()
		_ = outWrite.Close()
		_ = errWrite.Close()
		_ = outRead.Close()
		_ = errRead.Close()
		<-outDone
		<-errDone
		result.Stdout, result.Stderr = string(stdout.data), string(stderr.data)
		result.Truncated = stdout.truncated || stderr.truncated
		resultErr = errors.Join(resultErr, terminateErr, waitWinGetJobEmpty(job))
	}()
	aborted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = windows.TerminateJobObject(job, 1); close(aborted) })
	defer func() {
		if !stop() {
			<-aborted
		}
	}()
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if _, err = windows.ResumeThread(process.Thread); err != nil {
		return result, err
	}
	result.Started = true
	_ = outWrite.Close()
	_ = errWrite.Close()
	for {
		status, waitErr := windows.WaitForSingleObject(process.Process, 50)
		if waitErr != nil {
			return result, waitErr
		}
		if status == windows.WAIT_OBJECT_0 {
			break
		}
		if err = ctx.Err(); err != nil {
			return result, err
		}
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = windows.GetExitCodeProcess(process.Process, &result.ExitCode); err != nil {
		return result, err
	}
	closeProcess()
	// Successful completion requires both drained output and no remaining job
	// processes, including children that closed their output before finishing.
	drain := time.NewTimer(2 * time.Second)
	defer drain.Stop()
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	pendingOut, pendingErr := outDone, errDone
	for {
		active, err := winGetActiveProcesses(job)
		if err != nil {
			return result, err
		}
		if pendingOut == nil && pendingErr == nil && active == 0 {
			return result, errors.Join(outErr, errErr)
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-drain.C:
			return result, errors.New("WinGet left unfinished output or child work")
		case <-pendingOut:
			pendingOut = nil
		case <-pendingErr:
			pendingErr = nil
		case <-poll.C:
		}
	}
}

func waitWinGetJobEmpty(job windows.Handle) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		active, err := winGetActiveProcesses(job)
		if err != nil {
			return err
		}
		if active == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("WinGet child termination could not be confirmed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Layout of JOBOBJECT_BASIC_ACCOUNTING_INFORMATION from the Windows SDK.
func winGetActiveProcesses(job windows.Handle) (uint32, error) {
	var info struct {
		TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime int64
		TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses     uint32
	}
	err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	return info.ActiveProcesses, err
}
