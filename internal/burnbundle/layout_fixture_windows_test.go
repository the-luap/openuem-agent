//go:build openuem_burn_test

package burnbundle

import (
	"bytes"
	"debug/pe"
	"os"
	"testing"

	"github.com/open-uem/openuem-agent/internal/windowstest"
)

// This opt-in CI fixture invokes only the Go and pinned WiX build/extract tools.
// It never invokes a generated bootstrapper, payload or installer operation.
func TestOwnedWiXBundleLayout(t *testing.T) {
	for _, architecture := range []string{"386", "amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			fixture := windowstest.NewBurn(t, architecture, "machine")
			bundle := fixture.Path
			file, err := os.Open(bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			layout, err := Inspect(file, info.Size())
			if err != nil {
				if parsed, parseErr := pe.NewFile(file); parseErr == nil {
					t.Logf("generated PE: machine=%#x optional=%+v", parsed.Machine, parsed.OptionalHeader)
					for _, section := range parsed.Sections {
						t.Logf("section: %+v", section.SectionHeader)
					}
				}
				t.Fatal(err)
			}
			if layout.Architecture != architecture || layout.BundleCode != fixture.BundleCode {
				t.Fatalf("generated bundle identity mismatch: %+v / %+v", layout, fixture)
			}
			registration, err := ReadRegistration(t.Context(), file, info.Size())
			if err != nil {
				t.Fatal("native embedded registration", err)
			}
			view := "64"
			if architecture == "386" {
				view = "32"
			}
			want := Registration{BundleCode: fixture.BundleCode, Architecture: architecture, Version: fixture.Version, Scope: "machine", RegistryView: view}
			if registration != want {
				t.Fatalf("native registration mismatch: %+v / %+v", registration, want)
			}
			// Changing only the PE bundle code must invalidate the embedded binding.
			changed, err := os.ReadFile(bundle)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := pe.NewFile(bytes.NewReader(changed))
			if err != nil || parsed.Section(".wixburn") == nil {
				t.Fatal("owned Burn section missing")
			}
			changed[int(parsed.Section(".wixburn").Offset)+8] ^= 1
			if got, err := ReadRegistration(t.Context(), bytes.NewReader(changed), int64(len(changed))); err != ErrFormat || got != (Registration{}) {
				t.Fatal("changed header retained registration binding")
			}
			t.Logf("read-only generated bundle inspection: %+v", layout)
		})
	}
}
