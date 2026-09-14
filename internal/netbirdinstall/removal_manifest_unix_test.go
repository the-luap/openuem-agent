//go:build darwin || linux

package netbirdinstall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

// This repeats the original anonymous writer grammar independently of the new
// codec so a shared encoder/decoder bug cannot silently change retained bytes.
func legacyRemovalManifest(t *testing.T, m removalStageManifest) []byte {
	t.Helper()
	data, err := json.Marshal(struct {
		Schema     int
		RequestID  string
		Descriptor packageapi.Removal
		Objects    map[string]removalObject
	}{m.Schema, m.RequestID, m.Descriptor, m.Objects})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRemovalStageManifestRetainsOriginalWireAndPrivateFormatting(t *testing.T) {
	for _, optional := range []string{"present", "absent", "ancestors-absent"} {
		t.Run(optional, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			if optional != "present" {
				f.must(os.Remove(filepath.Join(f.root, removalCLI)))
				f.must(os.Remove(filepath.Join(f.root, removalDaemon)))
			}
			if optional == "ancestors-absent" {
				for _, name := range []string{"usr/local/bin", "usr/local", "usr", "Library/LaunchDaemons", "Library"} {
					f.must(os.Remove(filepath.Join(f.root, name)))
				}
			}
			observed, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			m := removalStageManifest{1, ownedRemovalRequest, observed.descriptor, observed.files.objects}
			owner := uint32(os.Geteuid())
			original := legacyRemovalManifest(t, m)
			data, err := encodeRemovalStageManifest(m, owner)
			f.must(err)
			if !bytes.Equal(data, original) {
				t.Fatal("manifest bytes changed from the original native writer")
			}
			decoded, err := decodeRemovalStageManifest(original, owner, m.RequestID, m.Descriptor)
			f.must(err)
			if !reflect.DeepEqual(*decoded, m) {
				t.Fatal("the original removal manifest lost retained evidence")
			}
			if _, err = json.Marshal(m); err == nil {
				t.Fatal("incidental serialization exposed private manifest metadata")
			}
			for _, format := range []string{"%v", "%+v", "%#v"} {
				if got := fmt.Sprintf(format, m); got != "[private NetBird removal manifest]" {
					t.Fatal("incidental formatting exposed private manifest metadata")
				}
			}
			stage, err := newRemovalStaging(t.Context(), f.root, owner, m.RequestID, observed)
			f.must(err)
			defer stage.close()
			persisted, err := os.ReadFile(filepath.Join(stage.path, "manifest.json"))
			f.must(err)
			if !bytes.Equal(persisted, original) {
				t.Fatal("the native owner did not persist its exact validated manifest")
			}
		})
	}
}

func TestRemovalStageManifestRejectsAmbiguousAndForeignWire(t *testing.T) {
	f := newRemovalFilesFixture(t)
	observed, err := ownedRemovalObserver(f)(t.Context())
	f.must(err)
	m := removalStageManifest{1, ownedRemovalRequest, observed.descriptor, observed.files.objects}
	original := string(legacyRemovalManifest(t, m))
	owner := uint32(os.Geteuid())
	for _, bad := range []string{
		"", "null", "{}", original + "\n", original + "{}",
		strings.Replace(original, `"Schema":1`, `"Schema":1,"Schema":1`, 1),
		strings.Replace(original, `"Schema":1`, `"schema":1`, 1),
		strings.Replace(original, `"Schema":1`, `"Schema":1.0`, 1),
		strings.Replace(original, `"Schema":1,`, ``, 1),
		strings.Replace(original, `"Schema":1`, `"Schema":null`, 1),
		strings.Replace(original, `"Schema":1`, `"Schema":1,"unknown":false`, 1),
		strings.Replace(original, `"Missing":false`, `"Missing":false,"Missing":false`, 1),
		strings.Replace(original, `"Missing":false`, `"missing":false`, 1),
		strings.Replace(original, `"Missing":false`, `"Missing":null`, 1),
		strings.Replace(original, `"Missing":false`, `"Missing":false,"unknown":0`, 1),
		strings.Repeat(" ", maxRemovalManifestBytes+1),
	} {
		if _, err := decodeRemovalStageManifest([]byte(bad), owner, m.RequestID, m.Descriptor); err == nil {
			t.Fatal("ambiguous or malformed manifest accepted")
		}
	}
	changed := m.Descriptor
	changed.StateDigest = strings.Repeat("e", 64)
	if _, err := decodeRemovalStageManifest([]byte(original), owner, m.RequestID, changed); err == nil {
		t.Fatal("manifest accepted under a changed original native descriptor")
	}
	if _, err := decodeRemovalStageManifest([]byte(original), owner, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", m.Descriptor); err == nil {
		t.Fatal("manifest accepted under a foreign original request")
	}
}

func TestRemovalStageManifestRejectsInvalidOwnershipGraph(t *testing.T) {
	f := newRemovalFilesFixture(t)
	observed, err := ownedRemovalObserver(f)(t.Context())
	f.must(err)
	original := removalStageManifest{1, ownedRemovalRequest, observed.descriptor, observed.files.objects}
	owner := uint32(os.Geteuid())
	for _, mutation := range []string{"unknown-path", "traversal", "missing-parent", "absent-parent", "file-parent", "file-as-directory", "missing-required", "missing-metadata", "unsafe-mode", "unsafe-owner", "hardlink", "bad-hash", "bad-acl", "foreign-link", "oversized", "too-many"} {
		t.Run(mutation, func(t *testing.T) {
			m := original
			m.Objects = maps.Clone(original.Objects)
			name := removalApp + "/Contents/MacOS/netbird"
			obj := m.Objects[name]
			switch mutation {
			case "unknown-path":
				m.Objects["etc/keep"] = obj
			case "traversal":
				m.Objects[removalApp+"/../../keep"] = obj
			case "missing-parent":
				delete(m.Objects, removalApp+"/Contents/MacOS")
			case "absent-parent":
				m.Objects["usr"] = removalObject{Missing: true}
			case "file-parent":
				m.Objects[removalApp+"/Contents/MacOS"] = obj
			case "file-as-directory":
				obj = m.Objects[removalApp+"/Contents/MacOS"]
			case "missing-required":
				obj = removalObject{Missing: true}
			case "missing-metadata":
				optional := m.Objects[removalCLI]
				optional.Missing = true
				m.Objects[removalCLI] = optional
			case "unsafe-mode":
				obj.Mode |= 0020
			case "unsafe-owner":
				obj.UID = owner + 1000
			case "hardlink":
				obj.Links = 2
			case "bad-hash":
				obj.Hash = "invalid"
			case "bad-acl":
				obj.ACL = "invalid"
			case "foreign-link":
				link := m.Objects[removalCLI]
				link.Link = "/other/keep"
				m.Objects[removalCLI] = link
			case "oversized":
				obj.Size = maxRemovalBytes + 1
			case "too-many":
				for i := range maxRemovalObjects {
					m.Objects[fmt.Sprintf("%s/Contents/MacOS/file-%d", removalApp, i)] = obj
				}
			}
			m.Objects[name] = obj
			if _, err := encodeRemovalStageManifest(m, owner); err == nil {
				t.Fatal("invalid retained ownership graph was serialized")
			}
			if _, err := decodeRemovalStageManifest(legacyRemovalManifest(t, m), owner, m.RequestID, m.Descriptor); err == nil {
				t.Fatal("invalid retained ownership graph was decoded")
			}
		})
	}
	// A writer failure must occur before even an empty stage is created.
	observed.files.objects[removalApp+"/unknown/keep"] = observed.files.objects[removalApp+"/Contents/MacOS/netbird"]
	if stage, err := newRemovalStaging(t.Context(), f.root, owner, original.RequestID, observed); err == nil || stage != nil {
		t.Fatal("invalid manifest was staged")
	}
	f.must(removalNoStages(t.Context(), f.root, owner))
}
