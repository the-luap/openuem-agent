//go:build darwin && cgo

package netbirdinstall

/*
#include <libproc.h>
#include <signal.h>
#include <errno.h>
#include <dlfcn.h>

static int openuem_removal_signal_available(void) {
    return dlsym(RTLD_DEFAULT, "proc_signal_with_audittoken") != NULL && dlsym(RTLD_DEFAULT, "SMCopyAllJobDictionaries") != NULL;
}

static int openuem_removal_signal(audit_token_t *token, int force) {
    int (*send_signal)(audit_token_t *, int) = dlsym(RTLD_DEFAULT, "proc_signal_with_audittoken");
    if (send_signal == NULL) return ENOSYS;
    return send_signal(token, force ? SIGKILL : SIGTERM);
}
*/
import "C"

import (
	"context"
	"errors"
	"reflect"
)

func nativeRemovalExecutionAvailable() bool {
	return removalProcessesSupported() && C.openuem_removal_signal_available() == 1
}

func removalProcessesQuiet(ctx context.Context, processes []removalProcess) (bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return false, ErrRemoval
	}
	quiet := true
	for _, process := range processes {
		if !process.valid() {
			return false, ErrRemoval
		}
		path, err := nativeRemovalAuditPath(ctx, process.Audit)
		if errors.Is(err, errRemovalProcessGone) {
			continue
		}
		if err != nil || path != process.Path {
			return false, ErrRemoval
		}
		quiet = false
	}
	return quiet, nil
}

func nativeSignalRemovalProcess(ctx context.Context, expected removalProcess, force bool) error {
	if ctx == nil || ctx.Err() != nil || !expected.valid() {
		return ErrRemoval
	}
	path, err := nativeRemovalAuditPath(ctx, expected.Audit)
	if errors.Is(err, errRemovalProcessGone) {
		return nil
	}
	if err != nil || path != expected.Path {
		return ErrRemoval
	}
	current, err := nativeRemovalProcess(ctx, int(expected.PID), path)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return ErrRemoval
	}
	return signalRemovalAudit(ctx, expected.Audit, force)
}

// The execution owner validates exact code/ownership before reaching this fixed
// token-bound primitive. There is no PID-only or process-group fallback.
func signalRemovalAudit(ctx context.Context, audit [8]uint32, force bool) error {
	if ctx == nil || ctx.Err() != nil || audit[5] <= 1 || audit[5] > 2147483647 || audit[7] == 0 {
		return ErrRemoval
	}
	var token C.audit_token_t
	for i, value := range audit {
		token.val[i] = C.uint32_t(value)
	}
	forced := C.int(0)
	if force {
		forced = 1
	}
	result := C.openuem_removal_signal(&token, forced)
	if ctx.Err() != nil || result != 0 && result != C.ESRCH {
		return ErrRemoval
	}
	return nil
}
