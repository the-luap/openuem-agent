//go:build darwin || linux

package netbirdinstall

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/open-uem/nats/netbirdcommand"
)

func TestRemovalRecoveryFilesRecognizeInterruptedMovesAndPurgeWithoutMutation(t *testing.T) {
	for _, phase := range []string{"before-move", "app-moved", "all-moved", "partial-purge", "empty-app", "purged", "receipts-partial", "receipts-absent", "partial-scaffold"} {
		t.Run(phase, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			owner := uint32(os.Geteuid())
			observed, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, owner, ownedRemovalRequest, observed)
			f.must(err)
			defer stage.close()
			if phase == "app-moved" {
				f.must(os.Rename(filepath.Join(f.root, removalApp), filepath.Join(stage.path, removalApp)))
			} else if phase != "before-move" {
				f.must(stage.move(t.Context()))
			}
			if phase == "partial-purge" {
				f.must(os.Remove(filepath.Join(stage.path, removalApp, "Contents/MacOS/netbird-ui")))
			}
			if phase == "empty-app" {
				names := slices.Collect(maps.Keys(stage.staged))
				slices.SortFunc(names, func(a, b string) int {
					if n := strings.Count(b, "/") - strings.Count(a, "/"); n != 0 {
						return n
					}
					return strings.Compare(b, a)
				})
				for _, name := range names {
					if strings.HasPrefix(name, removalApp+"/") {
						f.must(os.Remove(filepath.Join(stage.path, name)))
					}
				}
			}
			if phase == "purged" || phase == "receipts-partial" || phase == "receipts-absent" || phase == "partial-scaffold" {
				f.must(stage.purge(t.Context()))
			}
			if phase == "receipts-partial" || phase == "receipts-absent" || phase == "partial-scaffold" {
				f.must(os.Remove(filepath.Join(f.root, removalReceipt+".plist")))
			}
			if phase == "receipts-absent" || phase == "partial-scaffold" {
				f.must(os.Remove(filepath.Join(f.root, removalReceipt+".bom")))
			}
			if phase == "partial-scaffold" {
				f.must(os.Remove(filepath.Join(stage.path, "Library/LaunchDaemons")))
				f.must(os.Remove(filepath.Join(stage.path, "Library")))
			}
			f.must(stage.close())
			v, err := inspectRemovalRecoveryFiles(t.Context(), f.root, owner, ownedRemovalRequest, observed.descriptor)
			f.must(err)
			if !netbirdcommand.ValidDigest(v.digest) || v.manifest.manifest.Descriptor != observed.descriptor {
				t.Fatal("retained file inspection lost original descriptor or current fingerprint")
			}
			repeated, err := inspectRemovalRecoveryFiles(t.Context(), f.root, owner, ownedRemovalRequest, observed.descriptor)
			f.must(err)
			if repeated.digest != v.digest {
				t.Fatal("read-only file inspection changed stable retained evidence")
			}
			if v.source[removalApp].Missing != (phase != "before-move") {
				t.Fatal("source and relocated package roots were confused")
			}
			expectedReceipts := "present"
			if phase == "receipts-partial" {
				expectedReceipts = "partial"
			} else if phase == "receipts-absent" || phase == "partial-scaffold" {
				expectedReceipts = "absent"
			}
			if v.receipts != expectedReceipts {
				t.Fatal("missing receipt evidence became present or complete")
			}
			if _, err := json.Marshal(v); err == nil {
				t.Fatal("private remaining-file evidence was serialized incidentally")
			}
			if fmt.Sprintf("%+v %#v", v, v) != "[private NetBird removal recovery files] [private NetBird removal recovery files]" {
				t.Fatal("private remaining-file evidence was logged incidentally")
			}
			if removalNoStages(t.Context(), f.root, owner) == nil {
				t.Fatal("remaining-file inspection removed staging or released fresh-removal exclusion")
			}
		})
	}
}

func TestRemovalRecoveryFilesRejectChangedAndForeignObjects(t *testing.T) {
	for _, mutation := range []string{"source-missing-leaf", "source-added-leaf", "source-changed-leaf", "staged-changed-leaf", "staged-replaced-leaf", "staged-added-leaf", "staged-mode", "scaffold-extra", "scaffold-link", "receipt-replaced", "duplicate-root", "foreign-stage", "missing-manifest"} {
		t.Run(mutation, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			owner := uint32(os.Geteuid())
			observed, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, owner, ownedRemovalRequest, observed)
			f.must(err)
			defer stage.close()
			leaf := filepath.Join(removalApp, "Contents/MacOS/netbird-ui")
			if mutation != "source-missing-leaf" && mutation != "source-added-leaf" && mutation != "source-changed-leaf" {
				f.must(stage.move(t.Context()))
			}
			switch mutation {
			case "source-missing-leaf":
				f.must(os.Remove(filepath.Join(f.root, leaf)))
			case "source-added-leaf":
				f.write(removalApp+"/Contents/keep", []byte("unreviewed source object"), 0600)
			case "source-changed-leaf":
				f.must(os.WriteFile(filepath.Join(f.root, leaf), make([]byte, 32), 0755))
			case "staged-changed-leaf":
				f.must(os.WriteFile(filepath.Join(stage.path, leaf), make([]byte, 32), 0755))
			case "staged-replaced-leaf":
				path := filepath.Join(stage.path, leaf)
				data, err := os.ReadFile(path)
				f.must(err)
				f.must(os.Rename(path, filepath.Join(f.root, "saved-reviewed-leaf")))
				f.must(os.WriteFile(path, data, 0755))
			case "staged-added-leaf":
				f.must(os.WriteFile(filepath.Join(stage.path, removalApp, "keep"), []byte("unreviewed staged object"), 0600))
			case "staged-mode":
				f.must(os.Chmod(filepath.Join(stage.path, leaf), 0775))
			case "scaffold-extra":
				f.must(os.WriteFile(filepath.Join(stage.path, "keep"), []byte("unreviewed scaffold object"), 0600))
			case "scaffold-link":
				p := filepath.Join(stage.path, "usr")
				f.must(os.Rename(p, p+".saved"))
				f.must(os.Symlink(p+".saved", p))
			case "receipt-replaced":
				f.must(os.WriteFile(filepath.Join(f.root, removalReceipt+".plist"), []byte("unreviewed receipt"), 0600))
			case "duplicate-root":
				f.must(os.Symlink("/"+removalApp+"/Contents/MacOS/netbird", filepath.Join(f.root, removalCLI)))
			case "foreign-stage":
				f.must(os.Mkdir(filepath.Join(f.root, "Applications", removalStagePrefix+"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), 0700))
			case "missing-manifest":
				f.must(os.Remove(filepath.Join(stage.path, "manifest.json")))
			}
			if v, err := inspectRemovalRecoveryFiles(t.Context(), f.root, owner, ownedRemovalRequest, observed.descriptor); err == nil || v != nil {
				t.Fatal("changed or foreign current objects became owned recovery evidence")
			}
			if _, err := os.Lstat(stage.path); err != nil {
				t.Fatal("failed inspection removed the retained stage")
			}
		})
	}
}
