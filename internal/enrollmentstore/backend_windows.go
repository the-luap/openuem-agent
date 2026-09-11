package enrollmentstore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

type windowsBackend struct {
	directory string
	closed    atomic.Bool
}

// OpenNative requires a trusted existing parent. A newly created directory is
// owned by Administrators with only Local System/Administrators access, so an
// elevated installer and the Local System agent can share the same identity.
// Existing shared/user-owned directories fail without changing their permissions.
func OpenNative(directory string) (NativeBackend, error) {
	if !filepath.IsAbs(directory) {
		return nil, ErrUnavailable
	}
	directory = filepath.Clean(directory)
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		name, err := windows.UTF16PtrFromString(directory)
		if err != nil {
			return nil, ErrUnavailable
		}
		descriptor, err := systemDescriptor(true)
		if err != nil {
			return nil, ErrUnavailable
		}
		attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
		err = windows.CreateDirectory(name, &attributes)
		runtime.KeepAlive(descriptor)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, ErrUnavailable
		}
	}
	if err := checkSystemDirectory(directory); err != nil {
		return nil, err
	}
	return &windowsBackend{directory: directory}, nil
}

func (b *windowsBackend) Close() error { b.closed.Store(true); return nil }

// Inspect names without decrypting every absent bounded software slot. Any
// software-prefixed entry, even malformed, prevents a fresh enrollment fallback.
func (b *windowsBackend) hasSoftwareRecords() (bool, error) {
	if b.closed.Load() || checkSystemDirectory(b.directory) != nil {
		return false, ErrUnavailable
	}
	directory, err := os.Open(b.directory)
	if err != nil {
		return false, ErrUnavailable
	}
	defer directory.Close()
	for {
		entries, err := directory.Readdirnames(128)
		for _, name := range entries {
			if strings.HasPrefix(strings.ToLower(name), "software-") {
				return true, nil
			}
		}
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, ErrUnavailable
		}
	}
}

// Journal recovery decrypts only named slots after checking this installation's
// protected directory. Every software filename must be canonical; a result-only
// slot is included so the journal can reject partial restores.
func (b *windowsBackend) softwareRecordOrdinals() ([]int, error) {
	if b.closed.Load() || checkSystemDirectory(b.directory) != nil {
		return nil, ErrUnavailable
	}
	directory, err := os.Open(b.directory)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer directory.Close()
	seen := make(map[int]bool)
	count := 0
	for {
		names, err := directory.Readdirnames(128)
		for _, name := range names {
			count++
			if count > 20000 {
				return nil, ErrUnavailable
			}
			if !strings.HasPrefix(strings.ToLower(name), "software-") {
				continue
			}
			record, ok := strings.CutSuffix(name, ".dpapi")
			if !ok || !validRecord(record) {
				return nil, ErrUnavailable
			}
			for _, stage := range []string{"start", "result"} {
				if suffix, ok := strings.CutPrefix(record, "software-"+stage+"-v1-"); ok {
					n, parseErr := strconv.Atoi(suffix)
					if parseErr != nil {
						return nil, ErrUnavailable
					}
					seen[n] = true
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, ErrUnavailable
		}
	}
	ordinals := make([]int, 0, len(seen))
	for n := range seen {
		ordinals = append(ordinals, n)
	}
	slices.Sort(ordinals)
	return ordinals, nil
}

func (b *windowsBackend) Load(record string) ([]byte, error) {
	if !validRecord(record) || b.closed.Load() || checkSystemDirectory(b.directory) != nil {
		return nil, ErrUnavailable
	}
	path := filepath.Join(b.directory, record+".dpapi")
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrMissing
	}
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() <= 0 || after.Size() > maxProtectedSize || systemOnly(file) != nil {
		return nil, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, maxProtectedSize+1))
	if err != nil || len(data) > maxProtectedSize {
		return nil, ErrUnavailable
	}
	defer clear(data)
	return protectRecord(record, data, false)
}

func (b *windowsBackend) Create(record string, plaintext []byte) error {
	if !validRecord(record) || len(plaintext) == 0 || len(plaintext) > maxRecordSize || b.closed.Load() || checkSystemDirectory(b.directory) != nil {
		return ErrUnavailable
	}
	data, err := protectRecord(record, plaintext, true)
	if err != nil {
		return err
	}
	defer clear(data)
	temporary := filepath.Join(b.directory, ".enrollment-"+uuid.NewString()+".tmp")
	file, err := createSystemFile(temporary)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { file.Close(); os.Remove(temporary) }()
	if systemOnly(file) != nil {
		return ErrUnavailable
	}
	if _, err = file.Write(data); err != nil {
		return ErrUnavailable
	}
	if err = file.Sync(); err != nil {
		return ErrUnavailable
	}
	if err = file.Close(); err != nil {
		return ErrUnavailable
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return ErrUnavailable
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(b.directory, record+".dpapi"))
	if err != nil {
		return ErrUnavailable
	}
	// No REPLACE_EXISTING: a competing process must load the winning complete
	// record. WRITE_THROUGH completes publication before any claim can be sent.
	if err = windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return ErrUnavailable
	}
	return nil
}

func systemDescriptor(inherit bool) (*windows.SECURITY_DESCRIPTOR, error) {
	flags := ""
	if inherit {
		flags = "OICI"
	}
	return windows.SecurityDescriptorFromString("O:BAD:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;BA)")
}

func createSystemFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	descriptor, err := systemDescriptor(false)
	if err != nil {
		return nil, err
	}
	defer runtime.KeepAlive(descriptor)
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func checkSystemDirectory(path string) error {
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return ErrUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrUnavailable
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.IsDir() || !os.SameFile(before, after) {
		return ErrUnavailable
	}
	return systemOnly(file)
}

func systemOnly(file *os.File) error {
	security, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrUnavailable
	}
	defer runtime.KeepAlive(security)
	trusted := func(sid *windows.SID) bool {
		return sid != nil && sid.IsValid() && (sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := security.Owner()
	if err != nil || !trusted(owner) {
		return ErrUnavailable
	}
	dacl, _, err := security.DACL()
	if err != nil || dacl == nil || dacl.AceCount > 128 {
		return ErrUnavailable
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(dacl, uint32(i), &ace); err != nil || ace == nil {
			return ErrUnavailable
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrUnavailable
		}
		if ace.Mask != 0 && !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return ErrUnavailable
		}
	}
	return nil
}

func protectRecord(record string, data []byte, encrypt bool) ([]byte, error) {
	limit := maxProtectedSize
	if encrypt {
		limit = maxRecordSize
	}
	if !validRecord(record) || len(data) == 0 || len(data) > limit {
		return nil, ErrUnavailable
	}
	purpose := []byte("openuem/individual-agent/storage/v1/" + record)
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	entropy := windows.DataBlob{Size: uint32(len(purpose)), Data: &purpose[0]}
	var output windows.DataBlob
	var err error
	if encrypt {
		description, _ := windows.UTF16PtrFromString("OpenUEM individual agent identity")
		err = windows.CryptProtectData(&input, description, &entropy, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	} else {
		err = windows.CryptUnprotectData(&input, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	}
	runtime.KeepAlive(data)
	runtime.KeepAlive(purpose)
	if output.Data != nil {
		defer func() {
			clear(unsafe.Slice(output.Data, min(int(output.Size), maxProtectedSize)))
			windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
		}()
	}
	if err != nil || output.Data == nil || output.Size == 0 || int64(output.Size) > maxProtectedSize || (!encrypt && int64(output.Size) > maxRecordSize) {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...), nil
}
