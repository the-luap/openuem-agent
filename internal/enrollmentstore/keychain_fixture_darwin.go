//go:build darwin && cgo && openuem_keychain_test

package enrollmentstore

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>

// This bridge is compiled only for explicit isolated-keychain tests.
static OSStatus openuem_fixture_create(const char *path, const void *password,
    unsigned int size, SecKeychainRef *keychain) {
    *keychain = NULL;
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return status;
    return SecKeychainCreate(path, size, password, false, NULL, keychain);
}
*/
import "C"

import (
	"path/filepath"
	"runtime"
	"unsafe"
)

type temporaryKeychain struct {
	ref  C.SecKeychainRef
	path string
}

func createTemporaryKeychain(path string, password []byte) (*temporaryKeychain, error) {
	if !filepath.IsAbs(path) || filepath.Base(path) != "openuem-fixture.keychain" || len(password) == 0 || len(password) > 128 {
		return nil, ErrUnavailable
	}
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))
	var ref C.SecKeychainRef
	status := C.openuem_fixture_create(name, unsafe.Pointer(&password[0]), C.uint(len(password)), &ref)
	runtime.KeepAlive(password)
	if status != C.errSecSuccess {
		return nil, ErrUnavailable
	}
	return &temporaryKeychain{ref: ref, path: path}, nil
}

func (k *temporaryKeychain) Delete() error {
	if k.ref == 0 {
		return nil
	}
	status := C.SecKeychainDelete(k.ref)
	C.CFRelease(C.CFTypeRef(k.ref))
	k.ref = 0
	if status != C.errSecSuccess {
		return ErrUnavailable
	}
	return nil
}
func (k *temporaryKeychain) Lock() error {
	if C.SecKeychainLock(k.ref) != C.errSecSuccess {
		return ErrUnavailable
	}
	return nil
}
func (k *temporaryKeychain) Unlock(password []byte) error {
	if len(password) == 0 {
		return ErrUnavailable
	}
	status := C.SecKeychainUnlock(k.ref, C.uint(len(password)), unsafe.Pointer(&password[0]), C.Boolean(1))
	runtime.KeepAlive(password)
	if status != C.errSecSuccess {
		return ErrUnavailable
	}
	return nil
}
