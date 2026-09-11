//go:build openuem_burn_test

package deploy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"github.com/open-uem/nats/enrollment"
	"golang.org/x/sys/windows"
)

// RunOwnedBurnProcessFixture preserves the production command builder and native
// runner, exposing only the runner error for generated owned fixture diagnostics.
// Release builds never include this entry point. Output and arguments are omitted.
func RunOwnedBurnProcessFixture(ctx context.Context, plan enrollment.SoftwarePlan, path string) (SoftwareProcessResult, error) {
	if plan.Kind != "windows-burn" {
		return SoftwareProcessResult{}, ErrSoftwareProcess
	}
	var nativeErr error
	var drainErr error
	result, err := runSoftwareProcess(ctx, plan, path, func(ctx context.Context, executable, command string) (winGetProcessResult, error) {
		var result winGetProcessResult
		result, nativeErr = runWindowsProcessWithDrainObserver(ctx, executable, command, func(job windows.Handle, active uint32, stdout, stderr bool) {
			drainErr = fmt.Errorf("owned drain: active=%d stdout_pending=%t stderr_pending=%t images=%v", active, stdout, stderr, ownedJobImages(job))
		})
		return result, nativeErr
	})
	return result, errors.Join(err, nativeErr, drainErr)
}

// Inspect only this runner's retained job, with a fixed bound. Never enumerate
// unrelated processes or emit full paths, command lines or captured output.
func ownedJobImages(job windows.Handle) []string {
	// Native pointer alignment matters on ARM64 as well as field offsets.
	var info struct {
		Assigned, Count uint32
		PIDs            [32]uintptr
	}
	if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		return []string{fmt.Sprintf("query_failed(%v)", err)}
	}
	count := info.Count
	if count > 32 {
		return []string{"excessive"}
	}
	var images []string
	for i := uint32(0); i < count; i++ {
		pid := info.PIDs[i]
		if pid == 0 || pid > 0xffffffff {
			return []string{"invalid"}
		}
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			images = append(images, fmt.Sprintf("open_failed(%v)", err))
			continue
		}
		name := make([]uint16, 32768)
		length := uint32(len(name))
		err = windows.QueryFullProcessImageName(handle, 0, &name[0], &length)
		windows.CloseHandle(handle)
		if err != nil {
			images = append(images, fmt.Sprintf("image_failed(%v)", err))
			continue
		}
		images = append(images, filepath.Base(windows.UTF16ToString(name[:length])))
	}
	return images
}
