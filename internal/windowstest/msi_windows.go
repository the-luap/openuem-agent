//go:build windows && openuem_msi_test

// Package windowstest creates synthetic, uniquely identified Windows fixtures.
// It is available only under the explicit native MSI test build tag.
package windowstest

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

type MSI struct {
	Path, ProductCode, Version, RegistryPath string
	Properties                               map[string]string
}

// NewMSI writes an unsigned registry-only fixture: no files, scripts, custom
// actions, services, network sources or existing product/component identities.
// It does not install anything. The caller owns explicit install and removal.
func NewMSI(t *testing.T, directory string) MSI {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	guid := func() string { return "{" + strings.ToUpper(uuid.NewString()) + "}" }
	f := MSI{Path: filepath.Join(directory, "owned fixture.msi"), ProductCode: guid(), Version: "1.2.3", RegistryPath: `Software\OpenUEM-Owned-MSI-` + uuid.NewString(), Properties: map[string]string{
		"PLAIN": "literal-value", "SPACES": "  spaced value  ", "SLASH": `C:\path with spaces\`, "SLASHES": `two backslashes\\`, "UNICODE": "Unicode 🐈", "EMPTY": "", "SPECIAL": "literal ; $() & %PATH% = /qn",
	}}
	if runtime.GOARCH != "amd64" {
		t.Fatal("synthetic x64 MSI execution requires an amd64 Windows runner")
	}
	dll := windows.NewLazySystemDLL("msi.dll")
	call := func(name string, args ...uintptr) {
		t.Helper()
		code, _, _ := dll.NewProc(name).Call(args...)
		if code != 0 {
			t.Fatalf("owned MSI fixture %s returned %d", name, code)
		}
	}
	var database uint32
	path, _ := windows.UTF16PtrFromString(f.Path)
	call("MsiOpenDatabaseW", uintptr(unsafe.Pointer(path)), 3, uintptr(unsafe.Pointer(&database))) // MSIDBOPEN_CREATE
	defer dll.NewProc("MsiCloseHandle").Call(uintptr(database))
	execute := func(statement string) {
		t.Helper()
		query, _ := windows.UTF16PtrFromString(statement)
		var view uint32
		call("MsiDatabaseOpenViewW", uintptr(database), uintptr(unsafe.Pointer(query)), uintptr(unsafe.Pointer(&view)))
		defer dll.NewProc("MsiCloseHandle").Call(uintptr(view))
		call("MsiViewExecute", uintptr(view), 0)
		call("MsiViewClose", uintptr(view))
	}
	for _, statement := range []string{
		"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL PRIMARY KEY `Property`)",
		"CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL PRIMARY KEY `Directory`)",
		"CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)",
		"CREATE TABLE `Feature` (`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), `Title` CHAR(64), `Description` CHAR(255), `Display` SHORT, `Level` SHORT NOT NULL, `Directory_` CHAR(72), `Attributes` SHORT NOT NULL PRIMARY KEY `Feature`)",
		"CREATE TABLE `FeatureComponents` (`Feature_` CHAR(38) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Feature_`, `Component_`)",
		"CREATE TABLE `Registry` (`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL, `Name` CHAR(255), `Value` CHAR(0), `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`)",
		"CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)",
		"INSERT INTO `Directory` (`Directory`, `DefaultDir`) VALUES ('TARGETDIR', 'SourceDir')",
		fmt.Sprintf("INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, `KeyPath`) VALUES ('OwnedRegistry', '%s', 'TARGETDIR', 260, 'Marker')", guid()),
		"INSERT INTO `Feature` (`Feature`, `Title`, `Level`, `Attributes`) VALUES ('OwnedFeature', 'Owned synthetic registry', 1, 0)",
		"INSERT INTO `FeatureComponents` (`Feature_`, `Component_`) VALUES ('OwnedFeature', 'OwnedRegistry')",
		fmt.Sprintf("INSERT INTO `Registry` (`Registry`, `Root`, `Key`, `Name`, `Value`, `Component_`) VALUES ('Marker', 2, '%s', 'Marker', 'owned', 'OwnedRegistry')", f.RegistryPath),
	} {
		execute(statement)
	}
	properties := map[string]string{"ProductCode": f.ProductCode, "ProductVersion": f.Version, "ProductName": "OpenUEM owned MSI fixture", "ProductLanguage": "1033", "Manufacturer": "OpenUEM owned tests", "ALLUSERS": "1", "ARPSYSTEMCOMPONENT": "1", "INSTALLLEVEL": "1", "UpgradeCode": guid()}
	keys := make([]string, 0, len(f.Properties))
	for key := range f.Properties {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	properties["SecureCustomProperties"] = strings.Join(keys, ";")
	for key := range f.Properties {
		properties[key] = "default-that-must-be-replaced"
		execute(fmt.Sprintf("INSERT INTO `Registry` (`Registry`, `Root`, `Key`, `Name`, `Value`, `Component_`) VALUES ('R%s', 2, '%s', '%s', 'prefix:[%s]:suffix', 'OwnedRegistry')", key, f.RegistryPath, key, key))
	}
	for key, value := range properties {
		execute(fmt.Sprintf("INSERT INTO `Property` (`Property`, `Value`) VALUES ('%s', '%s')", key, value))
	}
	for _, action := range []struct {
		name     string
		sequence int
	}{
		{"CostInitialize", 800}, {"FileCost", 900}, {"CostFinalize", 1000}, {"InstallValidate", 1400}, {"InstallInitialize", 1500}, {"ProcessComponents", 1600}, {"UnpublishFeatures", 1800}, {"RemoveRegistryValues", 2600}, {"WriteRegistryValues", 5000}, {"RegisterUser", 6000}, {"RegisterProduct", 6100}, {"PublishFeatures", 6300}, {"PublishProduct", 6400}, {"InstallFinalize", 6600},
	} {
		execute(fmt.Sprintf("INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('%s', %d)", action.name, action.sequence))
	}
	var summary uint32
	call("MsiGetSummaryInformationW", uintptr(database), 0, 6, uintptr(unsafe.Pointer(&summary)))
	defer dll.NewProc("MsiCloseHandle").Call(uintptr(summary))
	for id, value := range map[uintptr]string{2: "Installation Database", 7: "x64;1033", 9: guid()} {
		text, _ := windows.UTF16PtrFromString(value)
		call("MsiSummaryInfoSetPropertyW", uintptr(summary), id, 30, 0, 0, uintptr(unsafe.Pointer(text))) // VT_LPSTR
	}
	call("MsiSummaryInfoSetPropertyW", uintptr(summary), 1, 2, 1252, 0, 0) // PID_CODEPAGE, VT_I2
	call("MsiSummaryInfoSetPropertyW", uintptr(summary), 14, 3, 500, 0, 0) // schema version, VT_I4
	call("MsiSummaryInfoSetPropertyW", uintptr(summary), 15, 3, 0, 0, 0)
	call("MsiSummaryInfoPersist", uintptr(summary))
	call("MsiDatabaseCommit", uintptr(database))
	return f
}
