//go:build darwin && cgo

package netbirdinstall

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <libproc.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    audit_token_t audit;
    uint64_t seconds;
    uint64_t microseconds;
    unsigned char hash[32];
    int hash_length;
} openuem_removal_process;

static int openuem_removal_process_available(void) {
    if (__builtin_available(macOS 11.3, *)) return 1;
    return 0;
}

static int openuem_removal_pid_path(int pid, char *path, uint32_t length) {
    errno = 0;
    int result = proc_pidpath(pid, path, length);
    if (result <= 0) return errno == ESRCH ? ESRCH : EIO;
    if (result >= length || path[result] != 0) return EIO;
    return 0;
}

static int openuem_removal_audit_path(audit_token_t *audit, char *path, uint32_t length) {
    if (__builtin_available(macOS 11.3, *)) {
        errno = 0;
        int result = proc_pidpath_audittoken(audit, path, length);
        if (result <= 0) return errno == ESRCH ? ESRCH : EIO;
        if (result >= length || path[result] != 0) return EIO;
        return 0;
    }
    return EIO;
}

static int openuem_removal_capture(int pid, const char *expected_path, const char *requirement_text, openuem_removal_process *result) {
    if (!openuem_removal_process_available() || pid <= 1) return EIO;
    int error = EIO;
    mach_port_t task = MACH_PORT_NULL;
    SecCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    CFStringRef source = NULL;
    CFDataRef audit_data = NULL;
    CFDictionaryRef attributes = NULL, information = NULL;
    audit_token_t before = {0}, after = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    struct proc_bsdinfo bsd = {0};
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    char signing_path[PROC_PIDPATHINFO_MAXSIZE] = {0};

    if (task_name_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS || task == MACH_PORT_NULL) goto done;
    if (task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&before, &count) != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT || before.val[5] != pid || before.val[7] == 0) goto done;
    if (openuem_removal_audit_path(&before, path, sizeof(path)) != 0 || strcmp(path, expected_path) != 0) goto done;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd)) != sizeof(bsd) || bsd.pbi_pid != pid || bsd.pbi_uid != before.val[1] || bsd.pbi_ruid != before.val[3]) goto done;

    source = CFStringCreateWithCString(NULL, requirement_text, kCFStringEncodingUTF8);
    if (source == NULL || SecRequirementCreateWithString(source, kSecCSDefaultFlags, &requirement) != errSecSuccess) goto done;
    audit_data = CFDataCreate(NULL, (const UInt8 *)&before, sizeof(before));
    if (audit_data == NULL) goto done;
    const void *key = kSecGuestAttributeAudit;
    const void *value = audit_data;
    attributes = CFDictionaryCreate(NULL, &key, &value, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (attributes == NULL || SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code) != errSecSuccess) goto done;
    // This validates the running guest and its static CodeDirectory together.
    // SecCodeCopyStaticCode alone does not establish that relationship.
    if (SecCodeCheckValidity(code, kSecCSStrictValidate | kSecCSNoNetworkAccess, requirement) != errSecSuccess) goto done;
    if (SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSDynamicInformation, &information) != errSecSuccess || information == NULL) goto done;
    CFTypeRef status_value = CFDictionaryGetValue(information, kSecCodeInfoStatus);
    uint32_t status = 0;
    if (status_value == NULL || CFGetTypeID(status_value) != CFNumberGetTypeID() || !CFNumberGetValue(status_value, kCFNumberSInt32Type, &status) || (status & kSecCodeStatusValid) == 0 || (status & kSecCodeStatusDebugged) != 0) goto done;
    CFTypeRef hash = CFDictionaryGetValue(information, kSecCodeInfoUnique);
    CFTypeRef executable = CFDictionaryGetValue(information, kSecCodeInfoMainExecutable);
    if (hash == NULL || CFGetTypeID(hash) != CFDataGetTypeID() || (CFDataGetLength(hash) != 20 && CFDataGetLength(hash) != 32)) goto done;
    if (executable == NULL || CFGetTypeID(executable) != CFURLGetTypeID() || !CFURLGetFileSystemRepresentation(executable, true, (UInt8 *)signing_path, sizeof(signing_path)) || strcmp(signing_path, expected_path) != 0) goto done;

    count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&after, &count) != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT || memcmp(&before, &after, sizeof(before)) != 0) goto done;
    memset(path, 0, sizeof(path));
    if (openuem_removal_audit_path(&before, path, sizeof(path)) != 0 || strcmp(path, expected_path) != 0) goto done;
    result->audit = before;
    result->seconds = bsd.pbi_start_tvsec;
    result->microseconds = bsd.pbi_start_tvusec;
    result->hash_length = (int)CFDataGetLength(hash);
    memcpy(result->hash, CFDataGetBytePtr(hash), result->hash_length);
    error = 0;
done:
    if (information != NULL) CFRelease(information);
    if (attributes != NULL) CFRelease(attributes);
    if (audit_data != NULL) CFRelease(audit_data);
    if (source != NULL) CFRelease(source);
    if (requirement != NULL) CFRelease(requirement);
    if (code != NULL) CFRelease(code);
    if (task != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), task);
    return error;
}
*/
import "C"

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

func removalProcessesSupported() bool {
	return os.Geteuid() == 0 && nativeRemovalProcessAPIAvailable()
}

func nativeRemovalProcessAPIAvailable() bool { return C.openuem_removal_process_available() == 1 }

func nativeRemovalPIDs(ctx context.Context) ([]int, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errRemovalProcesses
	}
	buffer := make([]C.int, maxRemovalPIDs+1)
	n := int(C.proc_listallpids(unsafe.Pointer(&buffer[0]), C.int(len(buffer)*int(unsafe.Sizeof(buffer[0])))))
	if n < 1 || n > maxRemovalPIDs || ctx.Err() != nil {
		return nil, errRemovalProcesses
	}
	result := make([]int, n)
	for index, pid := range buffer[:n] {
		result[index] = int(pid)
	}
	return result, nil
}

func nativeRemovalPIDPath(ctx context.Context, pid int) (string, error) {
	if ctx == nil || ctx.Err() != nil || pid < 1 || pid > 2147483647 {
		return "", errRemovalProcesses
	}
	var path [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	err := C.openuem_removal_pid_path(C.int(pid), &path[0], C.uint32_t(len(path)))
	if ctx.Err() != nil {
		return "", errRemovalProcesses
	}
	if err == C.ESRCH {
		return "", errRemovalProcessGone
	}
	if err != 0 {
		return "", errRemovalProcesses
	}
	return C.GoString(&path[0]), nil
}

func nativeRemovalProcess(ctx context.Context, pid int, path string) (removalProcess, error) {
	identifier := "netbird"
	if path == removalUIExecutable {
		identifier = "io.netbird.client"
	} else if path != removalCLIExecutable {
		return removalProcess{}, errRemovalProcesses
	}
	proof, err := captureRemovalProcess(ctx, pid, path, netbirdDeveloperRequirement+` and identifier "`+identifier+`"`)
	if err != nil || !proof.valid() {
		return removalProcess{}, errRemovalProcesses
	}
	return proof, nil
}

func nativeRemovalRecoveryProcess(ctx context.Context, requestID string, pid int, path string) (removalProcess, error) {
	identifier := removalRecoveryProcessIdentifier(requestID, path)
	if identifier == "" {
		return removalProcess{}, errRemovalProcesses
	}
	proof, err := captureRemovalProcess(ctx, pid, path, netbirdDeveloperRequirement+` and identifier "`+identifier+`"`)
	if err != nil || !proof.validRecovery(requestID) {
		return removalProcess{}, errRemovalProcesses
	}
	return proof, nil
}

// Production callers supply only fixed NetBird paths and requirements, including
// the two exact relocated executables derived from an original removal UUID.
// Owned native tests use their own ad-hoc signed inert process to verify the
// kernel identity boundary without executing any vendor code.
func captureRemovalProcess(ctx context.Context, pid int, path, requirement string) (removalProcess, error) {
	if ctx == nil || ctx.Err() != nil || pid <= 1 || pid > 2147483647 || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4095 || len(requirement) == 0 || len(requirement) > 4096 || strings.ContainsRune(path, 0) || strings.ContainsRune(requirement, 0) {
		return removalProcess{}, errRemovalProcesses
	}
	cpath, crequirement := C.CString(path), C.CString(requirement)
	defer C.free(unsafe.Pointer(cpath))
	defer C.free(unsafe.Pointer(crequirement))
	var result C.openuem_removal_process
	if C.openuem_removal_capture(C.int(pid), cpath, crequirement, &result) != 0 || ctx.Err() != nil {
		return removalProcess{}, errRemovalProcesses
	}
	proof := removalProcess{PID: uint32(pid), Path: path, StartedSeconds: uint64(result.seconds), StartedMicroseconds: uint64(result.microseconds)}
	for index, value := range result.audit.val {
		proof.Audit[index] = uint32(value)
	}
	proof.CodeHash = hex.EncodeToString(C.GoBytes(unsafe.Pointer(&result.hash[0]), C.int(result.hash_length)))
	return proof, nil
}

func nativeRemovalAuditPath(ctx context.Context, audit [8]uint32) (string, error) {
	if ctx == nil || ctx.Err() != nil || audit[5] <= 1 || audit[5] > 2147483647 || audit[7] == 0 {
		return "", errRemovalProcesses
	}
	var token C.audit_token_t
	for index, value := range audit {
		token.val[index] = C.uint32_t(value)
	}
	var path [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	err := C.openuem_removal_audit_path(&token, &path[0], C.uint32_t(len(path)))
	if ctx.Err() != nil {
		return "", errRemovalProcesses
	}
	if err == C.ESRCH {
		return "", errRemovalProcessGone
	}
	if err != 0 {
		return "", errRemovalProcesses
	}
	return C.GoString(&path[0]), nil
}
