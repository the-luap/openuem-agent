//go:build darwin && cgo

package netbirdinstall

import (
	"context"
	"strings"
	"testing"
)

func TestNativeRemovalJobEnumerationHasTypedCompleteSystemEvidence(t *testing.T) {
	job := strings.TrimSuffix(strings.TrimPrefix(ownedRemovalJob, `<plist version="1.0">`), `</plist>`)
	job = strings.Replace(job, "<key>PID</key>", "<key>OwnedPrivateCounter</key><string>owned-unselected-value</string><key>PID</key>", 1)
	unrelated := `<dict><key>Label</key><string>owned.unrelated</string><key>Program</key><string>/owned/unrelated</string><key>OwnedPrivate</key><string>owned-unrelated-private</string></dict>`
	for _, kind := range []string{"present", "absent", "duplicate-target", "duplicate-unrelated", "malformed-job", "missing-label", "empty-list", "wrong-root"} {
		t.Run(kind, func(t *testing.T) {
			items := unrelated + job
			switch kind {
			case "absent":
				items = unrelated
			case "duplicate-target":
				items += job
			case "duplicate-unrelated":
				items += unrelated
			case "malformed-job":
				items += `<string>invalid</string>`
			case "missing-label":
				items += `<dict/>`
			case "empty-list":
				items = ""
			}
			data := `<plist version="1.0"><array>` + items + `</array></plist>`
			if kind == "wrong-root" {
				data = `<plist version="1.0"><dict/></plist>`
			}
			output, present, err := nativeRemovalJobFixture(t.Context(), []byte(data))
			defer clear(output)
			if kind != "present" && kind != "absent" {
				if err != errRemovalProcesses || len(output) != 0 || present {
					t.Fatal("partial or ambiguous job inventory accepted", err)
				}
				return
			}
			if err != nil || present != (kind == "present") {
				t.Fatal("native job enumeration mismatch", err)
			}
			if strings.Contains(string(output), "owned-unselected-value") || strings.Contains(string(output), "owned-unrelated-private") || strings.Contains(string(output), "owned.unrelated") {
				t.Fatal("unselected native job data escaped")
			}
			read := func(context.Context) ([]byte, bool, error) { return append([]byte(nil), output...), present, nil }
			result, err := inspectRemovalLaunchd(t.Context(), true, read)
			if err != nil || result.Loaded != present || present && result.PID != 45 {
				t.Fatal("native job dictionary did not bind through the strict parser", err)
			}
		})
	}
}
