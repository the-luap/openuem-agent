package macbundle

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fixtureOptions(t *testing.T) Options {
	t.Helper()
	output := t.TempDir()
	if err := os.Chmod(output, 0700); err != nil {
		t.Fatal(err)
	}
	return Options{Agent: filepath.Join(t.TempDir(), "source-agent"), Output: output, Version: "0.12.0", Build: 42, Architecture: "arm64"}
}

// Structural, non-executable bytes exercise format rejection without launching
// a payload. Native tests separately assemble the actual compiled test image.
func fixtureImage(cpu macho.Cpu) []byte {
	var result bytes.Buffer
	for _, word := range []uint32{macho.Magic64, uint32(cpu), 0, uint32(macho.TypeExec), 2, 40, 4, 0, 5, 16, 0, 0, 0x32, 24, 1, 13 << 16, 26 << 16, 0} {
		_ = binary.Write(&result, binary.LittleEndian, word)
	}
	return result.Bytes()
}

func TestMachODeploymentTargetCannotOverstateMacOSCompatibility(t *testing.T) {
	for _, change := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[56:], 2) }, // iOS
		func(b []byte) { binary.LittleEndian.PutUint32(b[56:], 6) }, // Catalyst
		func(b []byte) { binary.LittleEndian.PutUint32(b[60:], 26<<16) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[60:], 13<<16|1) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[60:], 0) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[68:], 1) },                                            // Truncated tool array.
		func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 1); binary.LittleEndian.PutUint32(b[20:], 16) }, // Missing deployment target.
	} {
		data := fixtureImage(macho.CpuArm64)
		change(data)
		if err := verifyMachO(bytes.NewReader(data), "arm64"); !errors.Is(err, ErrSource) {
			t.Fatal("incompatible deployment metadata accepted", err)
		}
	}
	data := fixtureImage(macho.CpuArm64)
	data = append(data, data[48:]...)
	binary.LittleEndian.PutUint32(data[16:], 3)
	binary.LittleEndian.PutUint32(data[20:], 64)
	if err := verifyMachO(bytes.NewReader(data), "arm64"); !errors.Is(err, ErrSource) {
		t.Fatal("ambiguous deployment targets accepted", err)
	}
	// Older macOS commands are valid too, provided they do not claim another OS.
	data = fixtureImage(macho.CpuAmd64)[:64]
	binary.LittleEndian.PutUint32(data[20:], 32)
	binary.LittleEndian.PutUint32(data[48:], 0x24)
	binary.LittleEndian.PutUint32(data[52:], 16)
	binary.LittleEndian.PutUint32(data[56:], 11<<16)
	if err := verifyMachO(bytes.NewReader(data), "amd64"); err != nil {
		t.Fatal("compatible legacy macOS target rejected", err)
	}
}

func TestMachOTargetGuardRejectsOtherContainersTypesAndMissingEntrypoints(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		cpu := macho.CpuAmd64
		if architecture == "arm64" {
			cpu = macho.CpuArm64
		}
		data := fixtureImage(cpu)
		if err := verifyMachO(bytes.NewReader(data), architecture); err != nil {
			t.Fatal(err)
		}
		if err := verifyMachO(bytes.NewReader(data), "386"); !errors.Is(err, ErrSource) {
			t.Fatal("unsupported target accepted", err)
		}
	}
	for _, data := range [][]byte{nil, []byte("MZ fixture"), fixtureImage(macho.CpuAmd64), fixtureImage(macho.CpuArm64)[:31]} {
		if err := verifyMachO(bytes.NewReader(data), "arm64"); !errors.Is(err, ErrSource) {
			t.Fatal("foreign executable accepted", err)
		}
	}
	for _, kind := range []uint32{uint32(macho.TypeObj), uint32(macho.TypeDylib)} {
		data := fixtureImage(macho.CpuArm64)
		binary.LittleEndian.PutUint32(data[12:], kind)
		if err := verifyMachO(bytes.NewReader(data), "arm64"); !errors.Is(err, ErrSource) {
			t.Fatal("non-executable Mach-O accepted", err)
		}
	}
	data := fixtureImage(macho.CpuArm64)
	binary.LittleEndian.PutUint32(data[16:], 0)
	binary.LittleEndian.PutUint32(data[20:], 0)
	if err := verifyMachO(bytes.NewReader(data[:32]), "arm64"); !errors.Is(err, ErrSource) {
		t.Fatal("Mach-O without an entry point accepted", err)
	}
}

func TestBundleMetadataRequiresCanonicalReleaseValues(t *testing.T) {
	o := fixtureOptions(t)
	if !validOptions(o) {
		t.Fatal("valid build rejected")
	}
	for _, version := range []string{"", "v0.12.0", "0.12", "0.12.0-beta", "01.2.3", "1.2.3<key>", "1.2.3\n", "10000.2.3"} {
		o.Version = version
		if validOptions(o) {
			t.Fatal("invalid bundle release metadata accepted")
		}
	}
	o.Version = "0.12.0"
	for _, build := range []int{-1, 0, 10000} {
		o.Build = build
		if validOptions(o) {
			t.Fatal("invalid CFBundleVersion accepted")
		}
	}
}
