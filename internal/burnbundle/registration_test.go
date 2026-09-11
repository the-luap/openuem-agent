package burnbundle

import (
	"strings"
	"testing"
)

func registrationFixture(architecture string, modern, machine bool) (Layout, []byte) {
	layout := Layout{Architecture: architecture, BundleCode: fixtureCode}
	bitness := "yes"
	if architecture == "386" {
		bitness = "no"
	}
	identity := `Id="` + fixtureCode + `" PerMachine="yes"`
	if modern {
		identity = `Code="` + fixtureCode + `" Scope="perMachine"`
	}
	if !machine {
		identity = strings.ReplaceAll(strings.ReplaceAll(identity, `PerMachine="yes"`, `PerMachine="no"`), `Scope="perMachine"`, `Scope="perUser"`)
	}
	data := `<?xml version="1.0" encoding="utf-8"?><BurnManifest xmlns="` + burnNamespace + `" EngineVersion="4.0.6.0" ProtocolVersion="1" Win64="` + bitness + `"><Registration ` + identity + ` Version="1.2.3.4" ExecutableName="fixture.exe" ProviderKey="` + fixtureCode + `"><Arp DisplayName="Fixture" DisplayVersion="1.2.3.4" Publisher="OpenUEM" /></Registration><Chain /></BurnManifest>`
	return layout, []byte(data)
}

func TestRegistrationBindsExactHeaderAndScope(t *testing.T) {
	for _, architecture := range []string{"386", "amd64", "arm64"} {
		for _, modern := range []bool{false, true} {
			for _, machine := range []bool{false, true} {
				layout, data := registrationFixture(architecture, modern, machine)
				view, scope := "64", "machine"
				if architecture == "386" {
					view = "32"
				}
				if !machine {
					scope = "user"
				}
				want := Registration{BundleCode: fixtureCode, Architecture: architecture, Version: "1.2.3.4", Scope: scope, RegistryView: view}
				got, err := parseRegistration(layout, data)
				if err != nil || got != want {
					t.Fatalf("got %+v,%v want %+v", got, err, want)
				}
				got, err = parseRegistration(layout, append([]byte{0xef, 0xbb, 0xbf}, data...))
				if err != nil || got != want {
					t.Fatal("UTF-8 BOM rejected")
				}
			}
		}
	}
}

func TestRegistrationRejectsAmbiguityAndUnsupportedMetadata(t *testing.T) {
	layout, data := registrationFixture("amd64", false, true)
	changes := map[string][2]string{
		"namespace":              {burnNamespace, "urn:foreign"},
		"root":                   {"BurnManifest", "Foreign"},
		"header mismatch":        {fixtureCode, "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}"},
		"mixed identity":         {`Id="`, `Code="{00000000-0000-0000-0000-000000000001}" Id="`},
		"duplicate identity":     {`Id="`, `Id="{00000000-0000-0000-0000-000000000001}" Id="`},
		"duplicate registration": {`<Chain />`, `<Registration Id="` + fixtureCode + `" />`},
		"nested registration":    {`<Chain />`, `<Chain><Registration /></Chain>`},
		"duplicate ARP":          {`</Registration>`, `<Arp DisplayVersion="1.2.3.4" /></Registration>`},
		"nested ARP":             {`<Chain />`, `<Chain><Arp /></Chain>`},
		"ARP content":            {` /></Registration>`, `><Text /></Arp></Registration>`},
		"scope missing":          {` PerMachine="yes"`, ""},
		"scope unknown":          {`PerMachine="yes"`, `PerMachine="maybe"`},
		"display mismatch":       {`DisplayVersion="1.2.3.4"`, `DisplayVersion="1.2.3.5"`},
		"view mismatch":          {`Win64="yes"`, `Win64="no"`},
		"unknown protocol":       {`ProtocolVersion="1"`, `ProtocolVersion="2"`},
		"engine version":         {`EngineVersion="4.0.6.0"`, `EngineVersion="4"`},
		"root behavior":          {`Win64="yes"`, `Win64="yes" Unknown="true"`},
		"registration behavior":  {`PerMachine="yes"`, `PerMachine="yes" Unknown="true"`},
		"ARP behavior":           {`Publisher="OpenUEM"`, `Publisher="OpenUEM" Unknown="true"`},
		"version control":        {`Version="1.2.3.4"`, `Version="1.2.&#10;3.4"`},
		"DTD":                    {`<BurnManifest`, `<!DOCTYPE BurnManifest [<!ENTITY external SYSTEM "file:///private/test">]><BurnManifest`},
		"processing instruction": {`<Chain />`, `<?execute action?><Chain />`},
		"namespaced alias":       {`PerMachine="yes"`, `xmlns:x="urn:alias" PerMachine="yes" x:PerMachine="no"`},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			mutated := strings.ReplaceAll(string(data), change[0], change[1])
			if mutated == string(data) {
				t.Fatal("ineffective mutation")
			}
			got, err := parseRegistration(layout, []byte(mutated))
			if err != ErrFormat || got != (Registration{}) {
				t.Fatalf("accepted %+v %v", got, err)
			}
		})
	}
	_, modern := registrationFixture("amd64", true, true)
	for _, scope := range []string{"perUserOrMachine", "perMachineOrUser", "", "MACHINE"} {
		if _, err := parseRegistration(layout, []byte(strings.ReplaceAll(string(modern), "perMachine", scope))); err != ErrFormat {
			t.Fatal("flexible/unknown scope accepted")
		}
	}
	for _, invalid := range [][]byte{nil, append(data, data...), append(data, []byte("trailing")...), []byte(strings.Repeat("x", int(maxManifestSize)+1))} {
		if _, err := parseRegistration(layout, invalid); err != ErrFormat {
			t.Fatal("invalid document accepted")
		}
	}
}

func FuzzRegistration(f *testing.F) {
	for _, modern := range []bool{false, true} {
		_, data := registrationFixture("amd64", modern, true)
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		layout := Layout{Architecture: "amd64", BundleCode: fixtureCode}
		got, err := parseRegistration(layout, data)
		if err != nil {
			if err != ErrFormat || got != (Registration{}) {
				t.Fatal("partial identity")
			}
			return
		}
		if got.BundleCode != fixtureCode || got.Architecture != "amd64" || got.RegistryView != "64" || !registrationText(got.Version, 128) || (got.Scope != "machine" && got.Scope != "user") {
			t.Fatal("invalid accepted identity")
		}
	})
}
