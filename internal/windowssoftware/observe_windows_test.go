package windowssoftware

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestNativeWindowsSoftwareRegistrationIsExactAndViewBound(t *testing.T) {
	// Create only uniquely named synthetic machine registration keys. No package
	// is installed, no existing registration is changed and both views are removed.
	name := "OpenUEM-owned-observation-" + uuid.NewString()
	keys := map[string]registry.Key{}
	for _, view := range []struct {
		name   string
		access uint32
	}{{"32", registry.WOW64_32KEY}, {"64", registry.WOW64_64KEY}} {
		root, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallBranch, registry.CREATE_SUB_KEY|registry.ENUMERATE_SUB_KEYS|view.access)
		if err != nil {
			t.Fatal("owned machine fixture requires an administrative Windows test runner", err)
		}
		t.Cleanup(func() { root.Close() })
		key, opened, err := registry.CreateKey(root, name, registry.ALL_ACCESS|view.access)
		if err != nil || opened {
			t.Fatal("owned registration creation", opened, err)
		}
		keys[view.name] = key
		t.Cleanup(func() {
			key.Close()
			if err := registry.DeleteKey(root, name); err != nil {
				t.Error("owned registration cleanup", err)
			}
		})
		if err := key.SetStringValue("DisplayVersion", "1.2."+view.name); err != nil {
			t.Fatal(err)
		}
	}
	for _, view := range []string{"32", "64"} {
		r := Rule{Kind: "uninstall-key", UninstallKey: name, RegistryView: view, Version: "1.2." + view}
		o, err := Observe(t.Context(), r)
		if err != nil || !o.Matches(r) {
			t.Fatal("native view or exact version lost", view, o, err)
		}
		r.Version = "other-version"
		o, err = Observe(t.Context(), r)
		if err != nil || o.State != Present || o.Matches(r) {
			t.Fatal("different version reported absent or matching", o, err)
		}
	}
	r := Rule{Kind: "uninstall-key", UninstallKey: name, RegistryView: "64", Version: "1.2.64"}
	for _, write := range []func() error{
		func() error { return keys["64"].DeleteValue("DisplayVersion") },
		func() error { return keys["64"].SetExpandStringValue("DisplayVersion", "%USERNAME%") },
		func() error { return keys["64"].SetDWordValue("DisplayVersion", 123) },
		func() error { return keys["64"].SetStringValue("DisplayVersion", strings.Repeat("x", 129)) },
		func() error { return keys["64"].SetStringValue("DisplayVersion", " padded") },
		func() error { return keys["64"].SetStringValue("DisplayVersion", "") },
	} {
		if err := write(); err != nil {
			t.Fatal(err)
		}
		if o, err := Observe(t.Context(), r); !errors.Is(err, ErrObservation) || o.State != Unknown {
			t.Fatal("invalid registration became installed or absent", o, err)
		}
	}
	r.UninstallKey += "-missing"
	if o, err := Observe(t.Context(), r); err != nil || o.State != Absent {
		t.Fatal("missing exact key not absent", o, err)
	}
}

func TestNativeWindowsSoftwareMSIAbsenceAndStrictHelper(t *testing.T) {
	r := testRule()
	r.ProductCode = "{" + strings.ToUpper(uuid.NewString()) + "}"
	if o, err := Observe(t.Context(), r); err != nil || o.State != Absent {
		t.Fatal("native machine MSI absence", o, err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{`{"kind":"script","version":"1"}`, `{"kind":"msi-product","kind":"uninstall-key","version":"1"}`, strings.Repeat("x", maxMessage+1)} {
		command := exec.CommandContext(t.Context(), executable, helperArgument)
		command.Stdin = strings.NewReader(input)
		data, err := command.CombinedOutput()
		if err == nil || len(data) != 0 {
			t.Fatal("invalid native helper input did not fail silently", err)
		}
	}
}

func TestNativeWindowsSoftwareRejectsMalformedUTF16(t *testing.T) {
	for _, units := range [][]uint16{{0xD800}, {0xDC00}, {'1', 0, '2'}, {0xD800, 'x'}} {
		if _, ok := exactUTF16(units); ok {
			t.Fatal("malformed native string accepted")
		}
	}
	valid := utf16.Encode([]rune("1.2.🚀"))
	if value, ok := exactUTF16(valid); !ok || value != "1.2.🚀" {
		t.Fatal("valid surrogate pair lost")
	}
	// Exercise native REG_SZ buffer parsing using an owned key, including a
	// missing terminator that higher-level registry helpers normally conceal.
	name := "OpenUEM-owned-malformed-" + uuid.NewString()
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallBranch, registry.CREATE_SUB_KEY|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	key, opened, err := registry.CreateKey(root, name, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if err != nil || opened {
		t.Fatal(err)
	}
	defer func() {
		key.Close()
		if err := registry.DeleteKey(root, name); err != nil {
			t.Error(err)
		}
	}()
	r := Rule{Kind: "uninstall-key", UninstallKey: name, RegistryView: "64", Version: "1.2.3"}
	valueName, _ := windows.UTF16PtrFromString("DisplayVersion")
	setValue := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegSetValueExW")
	for _, units := range [][]uint16{{'1', '2'}, {'1', 0, '2', 0}, {0xD800, 0}} {
		var data bytes.Buffer
		if err := binary.Write(&data, binary.LittleEndian, units); err != nil {
			t.Fatal(err)
		}
		p := data.Bytes()
		if code, _, _ := setValue.Call(uintptr(key), uintptr(unsafe.Pointer(valueName)), 0, windows.REG_SZ, uintptr(unsafe.Pointer(&p[0])), uintptr(len(p))); code != 0 {
			t.Fatal("owned raw registry value write failed", code)
		}
		if o, err := Observe(t.Context(), r); !errors.Is(err, ErrObservation) || o.State != Unknown {
			t.Fatal("malformed registration accepted", o, err)
		}
	}
}
