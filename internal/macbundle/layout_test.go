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
	for _, word := range []uint32{macho.Magic64, uint32(cpu), 0, uint32(macho.TypeExec), 1, 16, 4, 0, 5, 16, 0, 0} {
		_ = binary.Write(&result, binary.LittleEndian, word)
	}
	return result.Bytes()
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
