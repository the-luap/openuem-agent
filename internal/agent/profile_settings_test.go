package agent

import (
	"maps"
	"strings"
	"testing"

	"github.com/open-uem/wingetcfg/wingetcfg"
)

func TestWinGetProfileRejectsMalformedParameters(t *testing.T) {
	base := map[string]any{"Ensure": "Present", "id": "Vendor.Product", "source": "winget", "uselatest": false}
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"Ensure", nil}, {"Ensure", true}, {"Ensure", "unknown private value"},
		{"id", nil}, {"id", 42}, {"id", []string{"Vendor.Product"}}, {"id", " "},
		{"version", true}, {"version", map[string]any{}}, {"version", nil},
		{"uselatest", "false"}, {"uselatest", 1}, {"uselatest", nil},
		{"source", "foreign"}, {"source", true}, {"source", nil},
	} {
		r := &wingetcfg.WinGetResource{Settings: maps.Clone(base)}
		r.Settings[tc.key] = tc.value
		if _, err := readWinGetProfileSettings(r); err == nil || strings.Contains(err.Error(), "private value") {
			t.Fatalf("%s = %#v: %v", tc.key, tc.value, err)
		}
	}
	if _, err := readWinGetProfileSettings(nil); err == nil {
		t.Fatal("nil resource accepted")
	}
	for _, missing := range []string{"Ensure", "id"} {
		r := &wingetcfg.WinGetResource{Settings: maps.Clone(base)}
		delete(r.Settings, missing)
		if _, err := readWinGetProfileSettings(r); err == nil {
			t.Fatalf("missing %s accepted", missing)
		}
	}
	r := &wingetcfg.WinGetResource{Settings: maps.Clone(base)}
	r.Settings["uselatest"], r.Settings["version"] = true, "1.2.3"
	if _, err := readWinGetProfileSettings(r); err == nil {
		t.Fatal("conflicting version intent accepted")
	}
}

func TestWinGetProfilePreservesSupportedPublisherSettings(t *testing.T) {
	for _, install := range []bool{false, true} {
		for _, latest := range []bool{false, true} {
			r, err := wingetcfg.NewWinGetPackageResource("task", "Owned fixture", "Vendor.Product", "winget", "1.2.3", latest, install)
			if err != nil {
				t.Fatal(err)
			}
			settings, err := readWinGetProfileSettings(r)
			if err != nil || settings.Action.PackageId != "Vendor.Product" || settings.KeepUpdated != latest || (settings.Ensure == "Present") != install {
				t.Fatalf("settings = %+v, %v", settings, err)
			}
			if latest && settings.Action.PackageVersion != "" || !latest && settings.Action.PackageVersion != "1.2.3" {
				t.Fatalf("version intent = %+v", settings)
			}
		}
	}
	r := &wingetcfg.WinGetResource{Settings: map[string]any{"Ensure": "Absent", "id": "Vendor.Product"}}
	if settings, err := readWinGetProfileSettings(r); err != nil || settings.KeepUpdated || settings.Action.PackageVersion != "" {
		t.Fatalf("optional defaults = %+v, %v", settings, err)
	}
}

func TestProfileSettingReadersRejectUnexpectedTypes(t *testing.T) {
	for _, resource := range []*wingetcfg.WinGetResource{nil, {Settings: map[string]any{"value": nil}}, {Settings: map[string]any{"value": 42}}, {Settings: map[string]any{"value": []string{"member"}}}} {
		if _, err := getStringKey(resource, "value", 32, false); err == nil {
			t.Fatal("non-string accepted")
		}
		if _, err := getBoolKey(resource, "value", false); err == nil {
			t.Fatal("non-boolean accepted")
		}
		if _, err := getCommaSeparatedStringKey(resource, "value", false); err == nil {
			t.Fatal("non-string members accepted")
		}
	}
	r := &wingetcfg.WinGetResource{Settings: map[string]any{"value": "a;b"}}
	if value, err := getCommaSeparatedStringKey(r, "value", false); err != nil || value != "'a', 'b'" {
		t.Fatalf("member format changed: %q, %v", value, err)
	}
	r.Settings["value"] = false
	if value, err := getBoolKey(r, "value", true); err != nil || value {
		t.Fatalf("explicit false = %v, %v", value, err)
	}
	delete(r.Settings, "value")
	if value, err := getBoolKey(r, "value", false); err != nil || value {
		t.Fatalf("missing optional boolean = %v, %v", value, err)
	}
	if _, err := getBoolKey(r, "value", true); err == nil {
		t.Fatal("missing required boolean accepted")
	}
}
