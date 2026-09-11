//go:build windows && openuem_msi_test

package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/windowstest"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestNativeWindowsSoftwareOwnedMSIInstallPropertiesAndRemove(t *testing.T) {
	if os.Getenv("OPENUEM_WINDOWS_MSI_FIXTURE") != "1" {
		t.Fatal("owned synthetic MSI execution requires explicit fixture opt-in")
	}
	f := windowstest.NewMSI(t, t.TempDir())
	plan := softwareProcessPlan()
	plan.Kind, plan.Artifact.Format = "windows-msi", "msi"
	plan.Artifact.URL = "https://example.invalid/fixture.msi"
	plan.Arguments, plan.MSIProperties = nil, f.Properties
	plan.Detection = enrollment.SoftwareDetection{Kind: "msi-product", ProductCode: f.ProductCode, Version: f.Version}
	if !plan.Valid() {
		t.Fatal("invalid owned MSI plan")
	}
	assertState := func(want string, wantCode uintptr) {
		t.Helper()
		product, _ := windows.UTF16PtrFromString(f.ProductCode)
		property, _ := windows.UTF16PtrFromString("State")
		var buffer [129]uint16
		size := uint32(len(buffer))
		code, _, _ := windows.NewLazySystemDLL("msi.dll").NewProc("MsiGetProductInfoExW").Call(uintptr(unsafe.Pointer(product)), 0, 4, uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
		if code != wantCode || code == 0 && windows.UTF16ToString(buffer[:]) != want {
			t.Fatal("native machine product state", code, windows.UTF16ToString(buffer[:]))
		}
	}
	assertState("", 1605)
	remove := plan
	remove.Operation, remove.Artifact, remove.MSIProperties = "remove", enrollment.SoftwareArtifact{}, nil
	removed := false
	t.Cleanup(func() {
		if removed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		result, err := RunSoftwareProcess(ctx, remove, "")
		if err != nil || result.ExitCode == nil || *result.ExitCode != 0 && *result.ExitCode != 1605 {
			t.Error("owned synthetic product cleanup failed", result, err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	logPath := filepath.Join(t.TempDir(), "owned-msi.log")
	result, err := runSoftwareProcess(ctx, plan, f.Path, func(ctx context.Context, executable, command string) (winGetProcessResult, error) {
		// Diagnostic logging belongs only to this synthetic test invocation.
		return runWindowsProcess(ctx, executable, command+` /l*v "`+logPath+`"`)
	})
	if err != nil || !result.Started || result.ExitCode == nil || *result.ExitCode != 0 {
		data, _ := os.ReadFile(logPath)
		// The engine writes UTF-16 diagnostics. Select failure context before
		// the long property footer, keeping logs bounded to this owned fixture.
		lines := strings.Split(strings.ReplaceAll(string(data), "\x00", ""), "\n")
		var diagnostic strings.Builder
		for i, line := range lines {
			if strings.Contains(line, "Return value 3") {
				for _, contextLine := range lines[max(0, i-15) : i+1] {
					diagnostic.WriteString(contextLine + "\n")
				}
			}
		}
		if diagnostic.Len() == 0 {
			diagnostic.WriteString(strings.Join(lines[max(0, len(lines)-30):], "\n"))
		}
		text := diagnostic.String()
		if len(text) > 20000 {
			text = text[:20000]
		}
		if result.ExitCode != nil {
			t.Log("owned MSI exit code", *result.ExitCode)
		}
		t.Fatalf("owned MSI installation failed: %v\n%s", err, text)
	}
	assertState("5", 0)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, f.RegistryPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range f.Properties {
		value, kind, err := key.GetStringValue(name)
		if err != nil || kind != registry.SZ || value != "prefix:"+expected+":suffix" {
			key.Close()
			t.Fatalf("native MSI property %s changed: %q, %v", name, value, err)
		}
	}
	key.Close()
	result, err = RunSoftwareProcess(ctx, remove, "")
	if err != nil || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatal("owned MSI removal failed", result, err)
	}
	removed = true
	assertState("", 1605)
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, f.RegistryPath, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		key.Close()
		t.Fatal("owned MSI registration survived removal")
	} else if err != windows.ERROR_FILE_NOT_FOUND {
		t.Fatal(err)
	}
	if !strings.HasPrefix(f.RegistryPath, `Software\OpenUEM-Owned-MSI-`) {
		t.Fatal("fixture scope changed")
	}
}
