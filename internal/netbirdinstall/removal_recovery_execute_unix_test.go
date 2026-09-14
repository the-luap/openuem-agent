//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func ownedRecoveryExecutionBackend(f *removalFilesFixture, descriptor packageapi.Removal, events *[]string) removalRecoveryExecutionBackend {
	read := ownedCurrentRecoveryReceiptReader(f)
	return removalRecoveryExecutionBackend{
		observe: func(ctx context.Context) (*removalRecoveryOwnership, error) {
			backend := ownedRecoveryOwnershipBackend(f, descriptor, "present", ownedRecoveryProcessBackend(nil))
			backend.read = read
			return inspectRemovalRecoveryOwnership(ctx, ownedRemovalRequest, descriptor, backend)
		},
		stop: func(ctx context.Context, observed *removalRecoveryOwnership) error {
			if observed.files.manifest.manifest.RequestID != ownedRemovalRequest || observed.files.manifest.manifest.Descriptor != descriptor {
				f.t.Fatal("native stop lost the original reviewed removal")
			}
			*events = append(*events, "stop")
			return nil
		},
		quiescent: func(ctx context.Context, path string) error {
			if path != filepath.Join(f.root, "Applications", removalStagePrefix+ownedRemovalRequest, removalApp) {
				f.t.Fatal("quiescence used a different original stage")
			}
			*events = append(*events, "quiet")
			return nil
		},
		read: read,
		forget: func(context.Context) error {
			*events = append(*events, "forget")
			for _, suffix := range []string{".plist", ".bom"} {
				if err := os.Remove(filepath.Join(f.root, removalReceipt+suffix)); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
			return nil
		},
	}
}

func TestRemovalRecoveryOwnerContinuesEveryManifestBackedInterruption(t *testing.T) {
	for _, phase := range []string{"before-move", "app-moved", "partial-purge", "purged", "bom-only", "plist-only", "absent", "partial-scaffold", "missing-scaffold"} {
		t.Run(phase, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			original, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
			f.must(err)
			defer stage.close()
			if phase == "app-moved" {
				f.must(os.Rename(filepath.Join(f.root, removalApp), filepath.Join(stage.path, removalApp)))
			} else if phase != "before-move" && phase != "missing-scaffold" {
				f.must(stage.move(t.Context()))
			}
			if phase == "partial-purge" {
				f.must(os.Remove(filepath.Join(stage.path, removalApp, "Contents/MacOS/netbird-ui")))
			}
			if phase == "purged" || phase == "bom-only" || phase == "plist-only" || phase == "absent" || phase == "partial-scaffold" {
				f.must(stage.purge(t.Context()))
			}
			if phase == "bom-only" || phase == "absent" || phase == "partial-scaffold" {
				f.must(os.Remove(filepath.Join(f.root, removalReceipt+".plist")))
			}
			if phase == "plist-only" || phase == "absent" || phase == "partial-scaffold" {
				f.must(os.Remove(filepath.Join(f.root, removalReceipt+".bom")))
			}
			if phase == "partial-scaffold" || phase == "missing-scaffold" {
				for i := len(removalStageParents) - 1; i > 0; i-- {
					f.must(os.Remove(filepath.Join(stage.path, removalStageParents[i])))
				}
			}
			f.must(stage.close())
			f.write("etc/netbird/config.json", []byte("retained local configuration"), 0600)
			var events []string
			backend := ownedRecoveryExecutionBackend(f, original.descriptor, &events)
			observed, err := backend.observe(t.Context())
			f.must(err)
			prepared, err := prepareRemovalRecovery(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original.descriptor, observed.digest, backend)
			f.must(err)
			defer prepared.Close()
			if len(events) != 0 {
				t.Fatal("recovery preparation mutated native state")
			}
			f.must(prepared.Run(t.Context()))
			f.must(prepared.Close())
			if prepared.Run(t.Context()) == nil {
				t.Fatal("recovery owner ran more than once")
			}
			stops, quiet, forgot := 0, 0, 0
			for _, event := range events {
				switch event {
				case "stop":
					stops++
				case "quiet":
					quiet++
				case "forget":
					forgot++
				default:
					t.Fatal("unexpected native recovery event")
				}
			}
			wantForget := 1
			if phase == "plist-only" || phase == "absent" || phase == "partial-scaffold" {
				wantForget = 0
			}
			if stops != 1 || quiet != 12 || forgot != wantForget || events[0] != "stop" {
				t.Fatal("native recovery lost mutation/quiescence sequence", events)
			}
			f.must(removalSourcesAbsent(t.Context(), f.root, uint32(os.Geteuid()), true))
			data, err := os.ReadFile(filepath.Join(f.root, "etc/netbird/config.json"))
			if err != nil || string(data) != "retained local configuration" {
				t.Fatal("recovery deleted unowned local state", err)
			}
		})
	}
}

func TestRemovalRecoveryOwnerPreservesChangedReviewAndInterruptedResults(t *testing.T) {
	for _, kind := range []string{"changed-review", "changed-runtime", "inspection-failed", "stop-failed", "source-changed-after-stop", "running-after-move", "forget-failed", "forget-partial", "new-source-at-forget", "final-query-failed", "cancelled", "closed"} {
		t.Run(kind, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			original, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
			f.must(err)
			defer stage.close()
			f.must(stage.close())
			var events []string
			backend := ownedRecoveryExecutionBackend(f, original.descriptor, &events)
			observe, stop, quiet, read, forget := backend.observe, backend.stop, backend.quiescent, backend.read, backend.forget
			observations, quietChecks := 0, 0
			backend.observe = func(ctx context.Context) (*removalRecoveryOwnership, error) {
				observations++
				if observations == 3 && kind == "inspection-failed" {
					return nil, ErrRemoval
				}
				v, err := observe(ctx)
				if err == nil && observations == 3 && kind == "changed-runtime" {
					v.digest = strings.Repeat("b", 64)
				}
				return v, err
			}
			backend.stop = func(ctx context.Context, v *removalRecoveryOwnership) error {
				if err := stop(ctx, v); err != nil {
					return err
				}
				if kind == "stop-failed" {
					return ErrRemoval
				}
				if kind == "source-changed-after-stop" {
					f.write(removalApp+"/Contents/keep", []byte("unknown retained child"), 0600)
				}
				return nil
			}
			backend.quiescent = func(ctx context.Context, path string) error {
				quietChecks++
				if quietChecks == 2 && kind == "running-after-move" {
					return ErrRemoval
				}
				return quiet(ctx, path)
			}
			backend.forget = func(ctx context.Context) error {
				if kind == "forget-failed" {
					events = append(events, "failed-forget")
					return ErrRemoval
				}
				if kind == "forget-partial" {
					f.must(os.Remove(filepath.Join(f.root, removalReceipt+".plist")))
					return nil
				}
				if kind == "new-source-at-forget" {
					f.write(removalApp+"/keep", []byte("new source remains"), 0600)
				}
				return forget(ctx)
			}
			backend.read = func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
				if _, err := os.Lstat(stage.path); os.IsNotExist(err) && kind == "final-query-failed" {
					return ErrRemoval
				}
				return read(ctx, path, args, limit, consume)
			}
			observed, err := backend.observe(t.Context())
			f.must(err)
			prepared, err := prepareRemovalRecovery(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original.descriptor, observed.digest, backend)
			f.must(err)
			defer prepared.Close()
			if kind == "changed-review" {
				f.write(removalApp+"/Contents/keep", []byte("changed after review"), 0600)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			if kind == "closed" {
				f.must(prepared.Close())
			}
			if prepared.Run(ctx) == nil {
				t.Fatal("changed or interrupted recovery acquired completion")
			}
			f.must(prepared.Close())
			if kind == "changed-review" || kind == "changed-runtime" || kind == "inspection-failed" || kind == "cancelled" || kind == "closed" {
				if len(events) != 0 {
					t.Fatal("unadmitted or changed review reached native mutation")
				}
			}
			if kind != "final-query-failed" {
				if _, err := os.Lstat(filepath.Join(stage.path, "manifest.json")); err != nil {
					t.Fatal("unconfirmed recovery erased retained original evidence", err)
				}
			}
			if kind == "new-source-at-forget" {
				if _, err := os.Lstat(filepath.Join(f.root, removalApp, "keep")); err != nil {
					t.Fatal("replacement package was removed", err)
				}
			}
		})
	}
}
