package windowssoftware

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const uninstallBranch = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

var productInfo = windows.NewLazySystemDLL("msi.dll").NewProc("MsiGetProductInfoExW")

func observeNative(ctx context.Context, r Rule) (Observation, error) {
	executable, err := os.Executable()
	if err != nil {
		return Observation{State: Unknown}, ErrObservation
	}
	command := exec.CommandContext(ctx, executable, helperArgument)
	command.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	return runObservation(ctx, command, r)
}

func readNative(r Rule) (Observation, error) {
	if r.Validate() != nil {
		return Observation{State: Unknown}, ErrObservation
	}
	if r.Kind == "msi-product" {
		return observeMSI(r.ProductCode, msiProperty)
	}
	return observeRegistration(r)
}

func msiProperty(product, property string) (string, uint32) {
	if productInfo.Find() != nil {
		return "", 1627
	}
	id, err := windows.UTF16PtrFromString(product)
	if err != nil {
		return "", 87
	}
	name, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return "", 87
	}
	var buffer [129]uint16
	length := uint32(len(buffer))
	// MSIINSTALLCONTEXT_MACHINE=4, with a NULL user SID. Reading installed
	// properties does not advertise, repair or configure the product.
	code, _, _ := productInfo.Call(uintptr(unsafe.Pointer(id)), 0, 4, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
	if code != 0 {
		return "", uint32(code)
	}
	if length >= uint32(len(buffer)) || buffer[length] != 0 {
		return "", 1627
	}
	value, ok := exactUTF16(buffer[:length])
	if !ok {
		return "", 1627
	}
	return value, 0
}

func observeRegistration(r Rule) (Observation, error) {
	unknown := Observation{State: Unknown}
	name, err := windows.UTF16PtrFromString(uninstallBranch + `\` + r.UninstallKey)
	if err != nil {
		return unknown, ErrObservation
	}
	view := uint32(windows.KEY_WOW64_64KEY)
	if r.RegistryView == "32" {
		view = windows.KEY_WOW64_32KEY
	}
	var key windows.Handle
	// REG_OPTION_OPEN_LINK=8 opens a final symbolic link itself. Only query rights
	// are requested; the selected WOW64 view is never merged with user inventory.
	err = windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, name, 8, windows.KEY_QUERY_VALUE|view, &key)
	if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
		return Observation{State: Absent}, nil
	}
	if err != nil {
		return unknown, ErrObservation
	}
	defer windows.RegCloseKey(key)
	linkName, _ := windows.UTF16PtrFromString("SymbolicLinkValue")
	var kind, size uint32
	if err = windows.RegQueryValueEx(key, linkName, nil, &kind, nil, &size); err != windows.ERROR_FILE_NOT_FOUND {
		return unknown, ErrObservation
	}
	valueName, _ := windows.UTF16PtrFromString("DisplayVersion")
	var buffer [258]byte
	size = uint32(len(buffer))
	err = windows.RegQueryValueEx(key, valueName, nil, &kind, &buffer[0], &size)
	if err != nil || kind != windows.REG_SZ || size < 4 || size > uint32(len(buffer)) || size%2 != 0 {
		return unknown, ErrObservation
	}
	units := make([]uint16, size/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(buffer[i*2:])
	}
	if units[len(units)-1] != 0 {
		return unknown, ErrObservation
	}
	version, ok := exactUTF16(units[:len(units)-1])
	if !ok || !validText(version, 128) {
		return unknown, ErrObservation
	}
	return Observation{State: Present, Version: version}, nil
}

// Windows UTF-16 conversion helpers replace unpaired surrogates. Observation
// evidence must instead reject malformed strings and embedded terminators.
func exactUTF16(units []uint16) (string, bool) {
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u == 0 {
			return "", false
		}
		if u >= 0xD800 && u <= 0xDBFF {
			if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
				return "", false
			}
			i++
		} else if u >= 0xDC00 && u <= 0xDFFF {
			return "", false
		}
	}
	return string(utf16.Decode(units)), true
}
