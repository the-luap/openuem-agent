package windowssoftware

import (
	"context"
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func preflightNative(ctx context.Context, r preflightRequest) error {
	executable, err := os.Executable()
	if err != nil {
		return ErrPreflight
	}
	command := exec.CommandContext(ctx, executable, preflightArgument)
	command.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	return runPreflight(ctx, command, r)
}

func readPreflight(r preflightRequest) error {
	if !r.valid() {
		return ErrPreflight
	}
	var process, native uint16
	if windows.IsWow64Process2(windows.CurrentProcess(), &process, &native) != nil {
		return ErrPreflight
	}
	// Emulated agent processes do not establish native package eligibility.
	if process != 0 || native != machineForArchitecture(r.Architecture) || runtime.GOARCH != r.Architecture {
		return ErrPreflight
	}
	version, err := readHostVersion()
	if err != nil || !compatibleOS(r.MinimumOS, version) {
		return ErrPreflight
	}
	if r.Path == "" {
		return nil
	}
	volume := filepath.VolumeName(r.Path)
	if len(volume) != 2 || volume[1] != ':' {
		return ErrPreflight
	}
	if r.Format == "exe" {
		return readPEArchitecture(r.Path, native)
	}
	return readMSIMetadata(r.Path, r.Architecture, *r.Detection)
}

func machineForArchitecture(architecture string) uint16 {
	switch architecture {
	case "amd64":
		return pe.IMAGE_FILE_MACHINE_AMD64
	case "arm64":
		return pe.IMAGE_FILE_MACHINE_ARM64
	}
	return 0
}

func readHostVersion() ([4]uint32, error) {
	var out [4]uint32
	native := windows.RtlGetVersion()
	if native == nil || native.MajorVersion != 10 || native.MinorVersion != 0 {
		return out, ErrPreflight
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return out, ErrPreflight
	}
	defer key.Close()
	build, kind, err := key.GetStringValue("CurrentBuildNumber")
	if err != nil || kind != registry.SZ || build != strconv.FormatUint(uint64(native.BuildNumber), 10) {
		return out, ErrPreflight
	}
	revision, kind, err := key.GetIntegerValue("UBR")
	if err != nil || kind != registry.DWORD || revision > 999999 {
		return out, ErrPreflight
	}
	secondBuild, secondKind, err := key.GetStringValue("CurrentBuildNumber")
	if err != nil || secondKind != registry.SZ || secondBuild != build {
		return out, ErrPreflight
	}
	secondRevision, secondKind, err := key.GetIntegerValue("UBR")
	if err != nil || secondKind != registry.DWORD || secondRevision != revision {
		return out, ErrPreflight
	}
	return [4]uint32{native.MajorVersion, native.MinorVersion, native.BuildNumber, uint32(revision)}, nil
}

func readPEArchitecture(path string, machine uint16) error {
	file, err := pe.Open(path)
	if err != nil {
		return ErrPreflight
	}
	defer file.Close()
	if file.Machine != machine || file.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || file.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		return ErrPreflight
	}
	if _, ok := file.OptionalHeader.(*pe.OptionalHeader64); !ok {
		return ErrPreflight
	}
	return nil
}

func readMSIMetadata(path, architecture string, r Rule) error {
	if r.Validate() != nil || r.Kind != "msi-product" {
		return ErrPreflight
	}
	// MSI handles stay on their creating thread. No session, install, repair or
	// configure API is used: only read-only database and summary queries.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dll := windows.NewLazySystemDLL("msi.dll")
	call := func(name string, args ...uintptr) uintptr { code, _, _ := dll.NewProc(name).Call(args...); return code }
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrPreflight
	}
	var database uint32
	if call("MsiOpenDatabaseW", uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&database))) != 0 {
		return ErrPreflight
	} // MSIDBOPEN_READONLY
	defer call("MsiCloseHandle", uintptr(database))
	queryProperty := func(property string) (string, error) {
		query, _ := windows.UTF16PtrFromString("SELECT `Value` FROM `Property` WHERE `Property` = '" + property + "'")
		var view uint32
		if call("MsiDatabaseOpenViewW", uintptr(database), uintptr(unsafe.Pointer(query)), uintptr(unsafe.Pointer(&view))) != 0 {
			return "", ErrPreflight
		}
		defer call("MsiCloseHandle", uintptr(view))
		if call("MsiViewExecute", uintptr(view), 0) != 0 {
			return "", ErrPreflight
		}
		defer call("MsiViewClose", uintptr(view))
		var record uint32
		if call("MsiViewFetch", uintptr(view), uintptr(unsafe.Pointer(&record))) != 0 {
			return "", ErrPreflight
		}
		defer call("MsiCloseHandle", uintptr(record))
		var buffer [129]uint16
		length := uint32(len(buffer))
		if call("MsiRecordGetStringW", uintptr(record), 1, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length))) != 0 || length >= uint32(len(buffer)) || buffer[length] != 0 {
			return "", ErrPreflight
		}
		value, ok := exactUTF16(buffer[:length])
		if !ok || !validText(value, 128) {
			return "", ErrPreflight
		}
		var extra uint32
		code := call("MsiViewFetch", uintptr(view), uintptr(unsafe.Pointer(&extra)))
		if extra != 0 {
			call("MsiCloseHandle", uintptr(extra))
		}
		if code != 259 {
			return "", ErrPreflight
		} // ERROR_NO_MORE_ITEMS
		return value, nil
	}
	product, err := queryProperty("ProductCode")
	if err != nil || product != r.ProductCode {
		return ErrPreflight
	}
	version, err := queryProperty("ProductVersion")
	if err != nil || version != r.Version {
		return ErrPreflight
	}
	var summary uint32
	if call("MsiGetSummaryInformationW", uintptr(database), 0, 0, uintptr(unsafe.Pointer(&summary))) != 0 {
		return ErrPreflight
	}
	defer call("MsiCloseHandle", uintptr(summary))
	var kind uint32
	var integer int32
	var stamp windows.Filetime
	var buffer [129]uint16
	length := uint32(len(buffer))
	if call("MsiSummaryInfoGetPropertyW", uintptr(summary), 7, uintptr(unsafe.Pointer(&kind)), uintptr(unsafe.Pointer(&integer)), uintptr(unsafe.Pointer(&stamp)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length))) != 0 || kind != 30 || length >= uint32(len(buffer)) || buffer[length] != 0 {
		return ErrPreflight
	}
	template, ok := exactUTF16(buffer[:length])
	if !ok {
		return ErrPreflight
	}
	platform, _, found := strings.Cut(template, ";")
	if !found || architecture == "amd64" && platform != "x64" || architecture == "arm64" && platform != "Arm64" || machineForArchitecture(architecture) == 0 {
		return ErrPreflight
	}
	return nil
}
