//go:build darwin || linux

package netbirdinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/netbirdcommand"
)

func TestRemovalStageManifestReadRetainsEvidenceWithoutMutation(t *testing.T) {
	f := newRemovalFilesFixture(t)
	observed, err := ownedRemovalObserver(f)(t.Context())
	f.must(err)
	owner := uint32(os.Geteuid())
	stage, err := newRemovalStaging(t.Context(), f.root, owner, ownedRemovalRequest, observed)
	f.must(err)
	f.must(stage.close())
	before, err := os.ReadFile(filepath.Join(stage.path, "manifest.json"))
	f.must(err)
	first, err := readRemovalStageManifest(t.Context(), f.root, owner, ownedRemovalRequest, observed.descriptor)
	f.must(err)
	second, err := readRemovalStageManifest(t.Context(), f.root, owner, ownedRemovalRequest, observed.descriptor)
	f.must(err)
	if !netbirdcommand.ValidDigest(first.digest) || first.digest != second.digest || first.manifest.RequestID != ownedRemovalRequest || first.manifest.Descriptor != observed.descriptor {
		t.Fatal("stable manifest evidence lost its exact original binding")
	}
	after, err := os.ReadFile(filepath.Join(stage.path, "manifest.json"))
	f.must(err)
	if !bytes.Equal(before, after) {
		t.Fatal("manifest inspection mutated its retained evidence")
	}
	for _, name := range []string{removalApp, removalCLI, removalDaemon, removalReceipt + ".plist", removalReceipt + ".bom"} {
		if _, err := os.Lstat(filepath.Join(f.root, name)); err != nil {
			t.Fatal("manifest inspection mutated original package state")
		}
	}
	if _, err = json.Marshal(first); err == nil {
		t.Fatal("incidental JSON exposed private filesystem evidence")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if fmt.Sprintf(format, first) != "[private NetBird removal manifest evidence]" {
			t.Fatal("incidental formatting exposed private filesystem evidence")
		}
	}
	if removalNoStages(t.Context(), f.root, owner) == nil {
		t.Fatal("reading a manifest implicitly cleared fresh-removal exclusion")
	}
}

func TestRemovalStageManifestReadRejectsUnsafeFilesAndAncestry(t *testing.T) {
	for _, mutation := range []string{"stage-mode", "manifest-mode", "manifest-link", "manifest-hardlink", "manifest-directory", "manifest-oversized", "manifest-empty", "manifest-corrupt", "foreign-reference", "foreign-descriptor", "stage-link", "parent-link", "parent-replaced", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			observed, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			owner := uint32(os.Geteuid())
			stage, err := newRemovalStaging(t.Context(), f.root, owner, ownedRemovalRequest, observed)
			f.must(err)
			f.must(stage.close())
			path := filepath.Join(stage.path, "manifest.json")
			id, descriptor := ownedRemovalRequest, observed.descriptor
			ctx := t.Context()
			switch mutation {
			case "stage-mode":
				f.must(os.Chmod(stage.path, 0755))
			case "manifest-mode":
				f.must(os.Chmod(path, 0644))
			case "manifest-link":
				f.must(os.Rename(path, path+".saved"))
				f.must(os.Symlink("manifest.json.saved", path))
			case "manifest-hardlink":
				f.must(os.Link(path, path+".saved"))
			case "manifest-directory":
				f.must(os.Remove(path))
				f.must(os.Mkdir(path, 0600))
			case "manifest-oversized":
				f.must(os.Truncate(path, maxRemovalManifestBytes+1))
			case "manifest-empty":
				f.must(os.Truncate(path, 0))
			case "manifest-corrupt":
				f.must(os.WriteFile(path, []byte(`{"Schema":1,"Schema":1}`), 0600))
			case "foreign-reference":
				id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
			case "foreign-descriptor":
				descriptor.StateDigest = strings.Repeat("e", 64)
			case "stage-link":
				f.must(os.Rename(stage.path, stage.path+".saved"))
				f.must(os.Symlink(stage.path+".saved", stage.path))
			case "parent-link":
				p := filepath.Join(f.root, "Applications")
				f.must(os.Rename(p, p+".saved"))
				f.must(os.Symlink(p+".saved", p))
			case "parent-replaced":
				p := filepath.Join(f.root, "Applications")
				f.must(os.Rename(p, p+".saved"))
				f.must(os.Mkdir(p, 0755))
				f.must(os.Rename(filepath.Join(p+".saved", stage.name), stage.path))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if v, err := readRemovalStageManifest(ctx, f.root, owner, id, descriptor); err == nil || v != nil {
				t.Fatal("unsafe or foreign retained manifest became recovery evidence")
			}
		})
	}
}
