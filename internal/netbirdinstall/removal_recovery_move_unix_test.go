//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRemovalRecoveryMovesOnlyRemainingOriginalSources(t *testing.T) {
	for _, phase := range []string{"before-move", "app-moved", "all-moved", "partial-purge", "missing-scaffold", "optional-absent"} {
		t.Run(phase, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			if phase == "optional-absent" {
				f.must(os.Remove(filepath.Join(f.root, removalCLI)))
				f.must(os.Remove(filepath.Join(f.root, removalDaemon)))
			}
			original, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
			f.must(err)
			defer stage.close()
			if phase == "app-moved" || phase == "partial-purge" {
				f.must(os.Rename(filepath.Join(f.root, removalApp), filepath.Join(stage.path, removalApp)))
			}
			if phase == "partial-purge" {
				f.must(os.Remove(filepath.Join(stage.path, removalApp, "Contents/MacOS/netbird-ui")))
			}
			if phase == "all-moved" {
				f.must(stage.move(t.Context()))
			}
			if phase == "missing-scaffold" {
				for i := len(removalStageParents) - 1; i > 0; i-- {
					f.must(os.Remove(filepath.Join(stage.path, removalStageParents[i])))
				}
			}
			f.must(stage.close())
			files, err := inspectRemovalRecoveryFiles(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original.descriptor)
			f.must(err)
			checks := 0
			after, err := moveRemovalRecoverySources(t.Context(), f.root, uint32(os.Geteuid()), files, func(context.Context) error { checks++; return nil })
			f.must(err)
			if checks != 2 || !removalRecoverySourcesEmpty(after) || after.receipts != files.receipts || !reflect.DeepEqual(after.manifest, files.manifest) {
				t.Fatal("continued move lost original or native quiescence evidence")
			}
			if phase == "partial-purge" {
				if _, err := os.Lstat(filepath.Join(stage.path, removalApp, "Contents/MacOS/netbird-ui")); !os.IsNotExist(err) {
					t.Fatal("previously purged payload was recreated", err)
				}
			}
			if phase == "optional-absent" {
				if !after.staged[removalCLI].Missing || !after.staged[removalDaemon].Missing {
					t.Fatal("originally absent optional payload was invented")
				}
			}
			if _, err := os.Lstat(filepath.Join(stage.path, "manifest.json")); err != nil {
				t.Fatal("move erased original manifest", err)
			}
			// The existing remaining-payload primitive must consume the continued
			// state, including a previously partial app and restored scaffolding.
			purged, err := purgeRemovalRecoveryPayload(t.Context(), f.root, uint32(os.Geteuid()), after, func(context.Context) error { return nil })
			f.must(err)
			if purged.receipts != "present" {
				t.Fatal("source move/purge forgot native receipts")
			}
		})
	}
}

func TestRemovalRecoveryMoveRejectsChangedSourceAndPreservesRejectedSubtree(t *testing.T) {
	for _, kind := range []string{"changed-review", "changed-root", "changed-child", "new-child", "foreign-stage", "occupied-destination", "scaffold-replaced", "not-quiet", "new-process", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			original, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
			f.must(err)
			defer stage.close()
			f.must(stage.close())
			files, err := inspectRemovalRecoveryFiles(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original.descriptor)
			f.must(err)
			if kind == "changed-review" {
				files.digest = "invalid"
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			checks := 0
			preserved := ""
			_, err = moveRemovalRecoverySources(ctx, f.root, uint32(os.Geteuid()), files, func(context.Context) error {
				checks++
				if checks == 1 {
					switch kind {
					case "changed-root":
						f.must(os.Rename(filepath.Join(f.root, removalApp), filepath.Join(f.root, "retained-original-app")))
						f.write(removalApp+"/keep", []byte("unreviewed replacement"), 0600)
						preserved = filepath.Join(f.root, removalApp, "keep")
					case "changed-child":
						preserved = filepath.Join(f.root, removalApp, "Contents/MacOS/netbird-ui")
						f.must(os.WriteFile(preserved, make([]byte, 32), 0755))
					case "new-child":
						f.write(removalApp+"/Contents/keep", []byte("unreviewed child"), 0600)
						preserved = filepath.Join(f.root, removalApp, "Contents/keep")
					case "foreign-stage":
						preserved = filepath.Join(f.root, "Applications", removalStagePrefix+"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
						f.must(os.Mkdir(preserved, 0700))
					case "occupied-destination":
						preserved = filepath.Join(stage.path, removalApp)
						f.must(os.Mkdir(preserved, 0700))
					case "scaffold-replaced":
						parent := filepath.Join(stage.path, "Applications")
						f.must(os.Rename(parent, filepath.Join(f.root, "retained-original-scaffold")))
						f.must(os.Mkdir(parent, 0700))
						preserved = parent
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
				t.Fatal("changed or incomplete native move acquired completion")
			}
			if preserved != "" {
				if _, err := os.Lstat(preserved); err != nil {
					t.Fatal("unknown/rejected data was lost or displaced", err)
				}
			}
			if _, err := os.Lstat(filepath.Join(stage.path, "manifest.json")); err != nil {
				t.Fatal("failed continuation lost original evidence", err)
			}
			if kind == "changed-review" && checks != 0 {
				t.Fatal("changed review reached runtime or native mutation")
			}
		})
	}
}
