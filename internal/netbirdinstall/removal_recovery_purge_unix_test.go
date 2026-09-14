//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRemovalRecoveryPurgeDeletesOnlyRemainingRelocatedOriginalPayload(t *testing.T) {
	for _, phase := range []string{"complete", "partial-purge", "purged", "partial-scaffold"} {
		t.Run(phase, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			original, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
			f.must(err)
			defer stage.close()
			f.must(stage.move(t.Context()))
			if phase == "partial-purge" {
				f.must(os.Remove(filepath.Join(stage.path, removalApp, "Contents/MacOS/netbird-ui")))
			}
			if phase == "purged" || phase == "partial-scaffold" {
				f.must(stage.purge(t.Context()))
			}
			if phase == "partial-scaffold" {
				f.must(os.Remove(filepath.Join(stage.path, "usr/local/bin")))
				f.must(os.Remove(filepath.Join(stage.path, "usr/local")))
			}
			f.must(stage.close())
			files, err := inspectRemovalRecoveryFiles(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original.descriptor)
			f.must(err)
			checks := 0
			after, err := purgeRemovalRecoveryPayload(t.Context(), f.root, uint32(os.Geteuid()), files, func(context.Context) error { checks++; return nil })
			f.must(err)
			if checks != 2 || after.receipts != "present" || !reflect.DeepEqual(after.source, files.source) || !reflect.DeepEqual(after.manifest, files.manifest) {
				t.Fatal("remaining-payload purge changed receipts, manifest or source evidence")
			}
			for name, obj := range after.staged {
				if removalPayload(name) && !obj.Missing {
					t.Fatal("approved remaining payload survived confirmed purge")
				}
			}
			if _, err := os.Lstat(filepath.Join(stage.path, "manifest.json")); err != nil {
				t.Fatal("payload purge erased original manifest", err)
			}
			if removalNoStages(t.Context(), f.root, uint32(os.Geteuid())) == nil {
				t.Fatal("payload-only purge removed the fresh-removal barrier")
			}
		})
	}
}

func TestRemovalRecoveryPurgeRejectsChangedFilesAndPreservesUnknownObjects(t *testing.T) {
	for _, kind := range []string{"source-present", "changed-review", "changed-leaf", "new-leaf", "replaced-parent", "new-source", "receipt-changed", "not-quiet", "new-process", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			original, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
			f.must(err)
			defer stage.close()
			if kind != "source-present" {
				f.must(stage.move(t.Context()))
			}
			f.must(stage.close())
			files, err := inspectRemovalRecoveryFiles(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original.descriptor)
			f.must(err)
			if kind == "changed-review" {
				files.digest = "invalid"
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			checks := 0
			var preserved string
			_, err = purgeRemovalRecoveryPayload(ctx, f.root, uint32(os.Geteuid()), files, func(context.Context) error {
				checks++
				if checks == 1 {
					switch kind {
					case "changed-leaf":
						preserved = filepath.Join(stage.path, removalApp, "Contents/MacOS/netbird-ui")
						f.must(os.WriteFile(preserved, make([]byte, 32), 0755))
					case "new-leaf":
						preserved = filepath.Join(stage.path, removalApp, "Contents/keep")
						f.must(os.WriteFile(preserved, []byte("unknown staged object"), 0600))
					case "replaced-parent":
						parent := filepath.Join(stage.path, removalApp, "Contents")
						saved := filepath.Join(f.root, "retained-original-parent")
						f.must(os.Rename(parent, saved))
						f.must(os.Mkdir(parent, 0755))
						children, err := os.ReadDir(saved)
						f.must(err)
						for _, child := range children {
							f.must(os.Rename(filepath.Join(saved, child.Name()), filepath.Join(parent, child.Name())))
						}
						// Nested payload files retain their original inode and bytes.
						// The new parent identity must still prevent their deletion.
						preserved = filepath.Join(parent, "MacOS/netbird-ui")
					case "new-source":
						preserved = filepath.Join(f.root, removalApp, "keep")
						f.write(removalApp+"/keep", []byte("unknown source"), 0600)
					case "receipt-changed":
						preserved = filepath.Join(f.root, removalReceipt+".plist")
						f.must(os.WriteFile(preserved, []byte("unknown receipt"), 0600))
					case "not-quiet":
						return ErrRemoval
					case "cancelled":
						cancel()
					}
				}
				if checks == 2 && kind == "new-process" {
					return ErrRemoval
				}
				return nil
			})
			if err == nil {
				t.Fatal("changed or incomplete recovery state acquired successful purge")
			}
			if preserved != "" {
				if _, err := os.Lstat(preserved); err != nil {
					t.Fatal("unknown object was deleted", err)
				}
			}
			if _, err := os.Lstat(filepath.Join(stage.path, "manifest.json")); err != nil {
				t.Fatal("failed purge erased retained original evidence", err)
			}
			if kind == "source-present" || kind == "changed-review" {
				if checks != 0 {
					t.Fatal("unprepared source or changed review reached quiescence/mutation")
				}
			}
		})
	}
}
