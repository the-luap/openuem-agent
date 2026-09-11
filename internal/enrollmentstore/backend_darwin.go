//go:build darwin && cgo

package enrollmentstore

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// A launchd system daemon must use a file-based keychain (Apple TN3137).
// Keep the file-keychain compatibility APIs inside this narrow bridge.
static OSStatus openuem_keychain_open(const char *path, SecKeychainRef *result) {
    *result = NULL;
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return status;
    status = SecKeychainOpen(path, result);
    if (status == errSecSuccess) {
        SecKeychainStatus state = 0;
        status = SecKeychainGetStatus(*result, &state);
        if (status == errSecSuccess && !(state & kSecUnlockStateStatus)) status = errSecInteractionNotAllowed;
    }
    if (status != errSecSuccess && *result) { CFRelease(*result); *result = NULL; }
    return status;
}

static CFMutableDictionaryRef openuem_keychain_query(const char *service, const char *record) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
    CFStringRef account = CFStringCreateWithCString(kCFAllocatorDefault, record, kCFStringEncodingUTF8);
    if (!query || !name || !account) {
        if (query) CFRelease(query); if (name) CFRelease(name); if (account) CFRelease(account);
        return NULL;
    }
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, name);
    CFDictionarySetValue(query, kSecAttrAccount, account);
    CFRelease(name); CFRelease(account);
    return query;
}

static OSStatus openuem_keychain_load(SecKeychainRef keychain, const char *service,
    const char *record, size_t limit, void **output, size_t *length) {
    *output = NULL; *length = 0;
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return status;
    CFMutableDictionaryRef query = openuem_keychain_query(service, record);
    if (!query) return errSecAllocate;
    const void *entries[] = {keychain};
    CFArrayRef search = CFArrayCreate(kCFAllocatorDefault, entries, 1, &kCFTypeArrayCallBacks);
    if (!search) { CFRelease(query); return errSecAllocate; }
    // Never search the user's default/login keychains or other applications.
    CFDictionarySetValue(query, kSecMatchSearchList, search);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFTypeRef value = NULL;
    status = SecItemCopyMatching(query, &value);
    CFRelease(search); CFRelease(query);
    if (status == errSecSuccess) {
        if (!value || CFGetTypeID(value) != CFDataGetTypeID()) status = errSecDecode;
        else {
            CFIndex size = CFDataGetLength((CFDataRef)value);
            if (size <= 0 || (size_t)size > limit) status = errSecDecode;
            else {
                *output = malloc((size_t)size);
                if (!*output) status = errSecAllocate;
                else { memcpy(*output, CFDataGetBytePtr((CFDataRef)value), (size_t)size); *length = (size_t)size; }
            }
        }
    }
    if (value) CFRelease(value);
    return status;
}

static OSStatus openuem_keychain_create(SecKeychainRef keychain, const char *service,
    const char *record, const void *data, size_t length) {
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return status;
    CFMutableDictionaryRef query = openuem_keychain_query(service, record);
    if (!query) return errSecAllocate;
    CFDataRef value = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)length);
    SecTrustedApplicationRef application = NULL;
    SecAccessRef access = NULL;
    CFArrayRef trusted = NULL;
    if (!value) { CFRelease(query); return errSecAllocate; }
    status = SecTrustedApplicationCreateFromPath(NULL, &application);
    if (status == errSecSuccess) {
        const void *entries[] = {application};
        trusted = CFArrayCreate(kCFAllocatorDefault, entries, 1, &kCFTypeArrayCallBacks);
        if (!trusted) status = errSecAllocate;
    }
    if (status == errSecSuccess)
        status = SecAccessCreate(CFSTR("OpenUEM individual agent identity"), trusted, &access);
    if (status == errSecSuccess) {
        CFDictionarySetValue(query, kSecUseKeychain, keychain);
        CFDictionarySetValue(query, kSecAttrAccess, access);
        CFDictionarySetValue(query, kSecAttrLabel, CFSTR("OpenUEM individual agent identity"));
        CFDictionarySetValue(query, kSecValueData, value);
        // Add is exclusive and commits one complete record. Never update a
        // competing pending key or an already issued identity implicitly.
        status = SecItemAdd(query, NULL);
    }
    if (access) CFRelease(access); if (trusted) CFRelease(trusted);
    if (application) CFRelease(application);
    CFRelease(value); CFRelease(query);
    return status;
}

// Inventory only this installation's item attributes. No key data, other
// services or default keychains are queried. Unknown software names also count.
static OSStatus openuem_keychain_has_software(SecKeychainRef keychain, const char *service, int *present) {
    *present = 0;
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return status;
    SecKeychainStatus state = 0;
    status = SecKeychainGetStatus(keychain, &state);
    if (status != errSecSuccess) return status;
    if (!(state & kSecUnlockStateStatus)) return errSecInteractionNotAllowed;
    CFMutableDictionaryRef query = openuem_keychain_query(service, "unused");
    if (!query) return errSecAllocate;
    CFDictionaryRemoveValue(query, kSecAttrAccount);
    const void *entries[] = {keychain};
    CFArrayRef search = CFArrayCreate(kCFAllocatorDefault, entries, 1, &kCFTypeArrayCallBacks);
    if (!search) { CFRelease(query); return errSecAllocate; }
    CFDictionarySetValue(query, kSecMatchSearchList, search);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFTypeRef value = NULL;
    status = SecItemCopyMatching(query, &value);
    CFRelease(search); CFRelease(query);
    if (status == errSecItemNotFound) status = errSecSuccess;
    else if (status == errSecSuccess) {
        if (!value || CFGetTypeID(value) != CFArrayGetTypeID()) status = errSecDecode;
        else for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)value); i++) {
            CFTypeRef item = CFArrayGetValueAtIndex((CFArrayRef)value, i);
            if (!item || CFGetTypeID(item) != CFDictionaryGetTypeID()) { status = errSecDecode; break; }
            CFTypeRef account = CFDictionaryGetValue((CFDictionaryRef)item, kSecAttrAccount);
            if (!account || CFGetTypeID(account) != CFStringGetTypeID()) { status = errSecDecode; break; }
            if (CFStringHasPrefix((CFStringRef)account, CFSTR("software-"))) { *present = 1; break; }
        }
    }
    if (value) CFRelease(value);
    return status;
}

static void openuem_secret_free(void *data, size_t length) {
    if (!data) return;
    volatile unsigned char *bytes = data;
    while (length--) *bytes++ = 0;
    free(data);
}
*/
import "C"

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/open-uem/nats/enrollment/keyfile"
)

type keychainBackend struct {
	mu       sync.Mutex
	keychain C.SecKeychainRef
	service  string
}

// OpenNative opens only the System keychain for the root launchd daemon. The
// installed agent must perform enrollment itself so the item's application ACL
// matches the same executable's signed identity when the service starts.
func OpenNative(directory string) (NativeBackend, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(directory) {
		return nil, ErrUnavailable
	}
	directory = filepath.Clean(directory)
	if err := keyfile.CreateDirectory(directory); err != nil {
		return nil, ErrUnavailable
	}
	digest := sha256.Sum256([]byte(directory))
	return openFileKeychain("/Library/Keychains/System.keychain", "org.openuem.agent.enrollment."+hex.EncodeToString(digest[:]))
}

func openFileKeychain(path, service string) (*keychainBackend, error) {
	if !filepath.IsAbs(path) || len(path) > 4096 || strings.ContainsRune(path, 0) || service == "" || len(service) > 255 || strings.ContainsAny(service, "\x00\r\n") {
		return nil, ErrUnavailable
	}
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))
	var keychain C.SecKeychainRef
	if C.openuem_keychain_open(name, &keychain) != C.errSecSuccess {
		return nil, ErrUnavailable
	}
	return &keychainBackend{keychain: keychain, service: service}, nil
}

func (b *keychainBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keychain != 0 {
		C.CFRelease(C.CFTypeRef(b.keychain))
		b.keychain = 0
	}
	return nil
}

func (b *keychainBackend) hasSoftwareRecords() (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keychain == 0 {
		return false, ErrUnavailable
	}
	service := C.CString(b.service)
	defer C.free(unsafe.Pointer(service))
	var present C.int
	if C.openuem_keychain_has_software(b.keychain, service, &present) != C.errSecSuccess {
		return false, ErrUnavailable
	}
	return present != 0, nil
}

func (b *keychainBackend) Load(record string) ([]byte, error) {
	if !validRecord(record) {
		return nil, ErrUnavailable
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keychain == 0 {
		return nil, ErrUnavailable
	}
	service := C.CString(b.service)
	defer C.free(unsafe.Pointer(service))
	name := C.CString(record)
	defer C.free(unsafe.Pointer(name))
	var output unsafe.Pointer
	var length C.size_t
	status := C.openuem_keychain_load(b.keychain, service, name, C.size_t(maxRecordSize), &output, &length)
	if output != nil {
		defer C.openuem_secret_free(output, length)
	}
	if status == C.errSecItemNotFound {
		return nil, ErrMissing
	}
	if status != C.errSecSuccess || output == nil || length == 0 || length > maxRecordSize {
		return nil, ErrUnavailable
	}
	return C.GoBytes(output, C.int(length)), nil
}

func (b *keychainBackend) Create(record string, plaintext []byte) error {
	if !validRecord(record) || len(plaintext) == 0 || len(plaintext) > maxRecordSize {
		return ErrUnavailable
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keychain == 0 {
		return ErrUnavailable
	}
	service := C.CString(b.service)
	defer C.free(unsafe.Pointer(service))
	name := C.CString(record)
	defer C.free(unsafe.Pointer(name))
	status := C.openuem_keychain_create(b.keychain, service, name, unsafe.Pointer(&plaintext[0]), C.size_t(len(plaintext)))
	runtime.KeepAlive(plaintext)
	if status == C.errSecDuplicateItem {
		return ErrExists
	}
	if status != C.errSecSuccess {
		return ErrUnavailable
	}
	return nil
}
