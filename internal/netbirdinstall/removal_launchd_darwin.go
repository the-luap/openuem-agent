//go:build darwin && cgo

package netbirdinstall

/*
#cgo LDFLAGS: -framework ServiceManagement -framework CoreFoundation
#include <ServiceManagement/ServiceManagement.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <dlfcn.h>

static int openuem_removal_job_data(CFArrayRef jobs, CFDataRef *output) {
    if (jobs == NULL || CFGetTypeID(jobs) != CFArrayGetTypeID()) return -1;
    CFIndex count = CFArrayGetCount(jobs);
    if (count < 1 || count > 8192) return -1;
    CFMutableSetRef labels = CFSetCreateMutable(NULL, 0, &kCFTypeSetCallBacks);
    if (labels == NULL) return -1;
    CFDictionaryRef found = NULL;
    int result = -1;
    for (CFIndex index = 0; index < count; index++) {
        CFTypeRef job = CFArrayGetValueAtIndex(jobs, index);
        if (CFGetTypeID(job) != CFDictionaryGetTypeID()) goto done;
        CFTypeRef label = CFDictionaryGetValue(job, CFSTR("Label"));
        if (label == NULL || CFGetTypeID(label) != CFStringGetTypeID() || CFStringGetLength(label) < 1 || CFStringGetLength(label) > 1024 || CFSetContainsValue(labels, label)) goto done;
        CFSetAddValue(labels, label);
        if (CFEqual(label, CFSTR("netbird"))) found = job;
    }
    if (found == NULL) { result = 0; goto done; }
    CFMutableDictionaryRef selected = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (selected == NULL) goto done;
    CFStringRef keys[] = { CFSTR("Label"), CFSTR("Program"), CFSTR("ProgramArguments"), CFSTR("PID"), CFSTR("EnvironmentVariables"), CFSTR("UserName"), CFSTR("RootDirectory"), CFSTR("WorkingDirectory") };
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
        CFTypeRef value = CFDictionaryGetValue(found, keys[i]);
        if (value != NULL) CFDictionarySetValue(selected, keys[i], value);
    }
    *output = CFPropertyListCreateData(NULL, selected, kCFPropertyListXMLFormat_v1_0, 0, NULL);
    CFRelease(selected);
    if (*output != NULL && CFDataGetLength(*output) > 0 && CFDataGetLength(*output) <= 64*1024) result = 1;
done:
    CFRelease(labels);
    return result;
}

static int openuem_removal_system_job(CFDataRef *output) {
    // No replacement API is provided for this read-only system-domain query.
    // A removed/unavailable API or changed dictionary shape fails closed.
    CFArrayRef (*copy_jobs)(CFStringRef) = dlsym(RTLD_DEFAULT, "SMCopyAllJobDictionaries");
    if (copy_jobs == NULL) return -1;
    CFArrayRef jobs = copy_jobs(kSMDomainSystemLaunchd);
    int result = openuem_removal_job_data(jobs, output);
    if (jobs != NULL) CFRelease(jobs);
    return result;
}

static int openuem_removal_fixture_jobs(const void *bytes, CFIndex length, CFDataRef *output) {
    CFDataRef data = CFDataCreate(NULL, bytes, length);
    if (data == NULL) return -1;
    CFPropertyListRef jobs = CFPropertyListCreateWithData(NULL, data, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(data);
    int result = openuem_removal_job_data(jobs, output);
    if (jobs != NULL) CFRelease(jobs);
    return result;
}
*/
import "C"

import (
	"context"
	"unsafe"
)

func nativeRemovalJob(ctx context.Context) ([]byte, bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, false, errRemovalProcesses
	}
	var output C.CFDataRef
	result := C.openuem_removal_system_job(&output)
	return removalJobData(ctx, result, output)
}

func removalJobData(ctx context.Context, result C.int, output C.CFDataRef) ([]byte, bool, error) {
	if output != 0 {
		defer C.CFRelease(C.CFTypeRef(output))
	}
	if result < 0 || result > 1 || ctx.Err() != nil || result == 0 && output != 0 || result == 1 && output == 0 {
		return nil, false, errRemovalProcesses
	}
	if result == 0 {
		return nil, false, nil
	}
	n := C.CFDataGetLength(output)
	if n < 1 || n > 64<<10 {
		return nil, false, errRemovalProcesses
	}
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(output)), C.int(n)), true, nil
}

// This bounded adapter is only used by owned native tests. It validates the same
// typed CoreFoundation enumeration without registering or modifying host jobs.
func nativeRemovalJobFixture(ctx context.Context, data []byte) ([]byte, bool, error) {
	if ctx == nil || ctx.Err() != nil || len(data) == 0 || len(data) > 64<<10 {
		return nil, false, errRemovalProcesses
	}
	var output C.CFDataRef
	result := C.openuem_removal_fixture_jobs(unsafe.Pointer(&data[0]), C.CFIndex(len(data)), &output)
	return removalJobData(ctx, result, output)
}
