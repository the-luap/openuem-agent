//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func ownedCurrentRecoveryReceiptReader(f *removalFilesFixture) packageReader {
	return func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
		_, plistErr := os.Lstat(filepath.Join(f.root, removalReceipt+".plist"))
		_, bomErr := os.Lstat(filepath.Join(f.root, removalReceipt+".bom"))
		if plistErr != nil && !os.IsNotExist(plistErr) || bomErr != nil && !os.IsNotExist(bomErr) {
			f.t.Fatal("owned receipt fixture unavailable")
		}
		phase := "present"
		if plistErr != nil && bomErr != nil {
			phase = "absent"
		} else if plistErr != nil {
			phase = "bom-only"
		} else if bomErr != nil {
			phase = "plist-only"
		}
		return ownedRecoveryReceiptReader(f, phase)(ctx, path, args, limit, consume)
	}
}

func ownedRecoveryCompletionFixture(t *testing.T, phase string) (*removalFilesFixture, *removalRecoveryFiles, string) {
	t.Helper()
	f := newRemovalFilesFixture(t)
	original, err := ownedRemovalObserver(f)(t.Context())
	f.must(err)
	stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
	f.must(err)
	defer stage.close()
	f.must(stage.move(t.Context()))
	if phase != "payload" {
		f.must(stage.purge(t.Context()))
	}
	if phase == "bom-only" || phase == "absent" || phase == "partial-scaffold" {
		f.must(os.Remove(filepath.Join(f.root, removalReceipt+".plist")))
	}
	if phase == "plist-only" || phase == "absent" || phase == "partial-scaffold" {
		f.must(os.Remove(filepath.Join(f.root, removalReceipt+".bom")))
	}
	if phase == "partial-scaffold" {
		f.must(os.Remove(filepath.Join(stage.path, "Library/LaunchDaemons")))
		f.must(os.Remove(filepath.Join(stage.path, "Library")))
	}
	f.must(stage.close())
	files, err := inspectRemovalRecoveryFiles(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original.descriptor)
	f.must(err)
	return f, files, stage.path
}

func TestRemovalRecoveryCompletesEachExactNativeReceiptState(t *testing.T) {
	for _, phase := range []string{"present", "bom-only", "plist-only", "absent"} {
		t.Run(phase, func(t *testing.T) {
			f, files, stage := ownedRecoveryCompletionFixture(t, phase)
			forgot, quiet := 0, 0
			after, err := completeRemovalRecoveryReceipts(t.Context(), f.root, uint32(os.Geteuid()), files, removalRecoveryReceiptBackend{
				read: ownedCurrentRecoveryReceiptReader(f),
				forget: func(context.Context) error {
					forgot++
					if phase != "present" && phase != "bom-only" {
						t.Fatal("orphan or absent receipt reached native forget")
					}
					for _, suffix := range []string{".plist", ".bom"} {
						if err := os.Remove(filepath.Join(f.root, removalReceipt+suffix)); err != nil && !os.IsNotExist(err) {
							return err
						}
					}
					return nil
				},
				quiescent: func(context.Context) error { quiet++; return nil },
			})
			f.must(err)
			wantForget := 0
			if phase == "present" || phase == "bom-only" {
				wantForget = 1
			}
			if forgot != wantForget || quiet != 3 || after.receipts != "absent" || !reflect.DeepEqual(after.manifest, files.manifest) || !reflect.DeepEqual(after.staged, files.staged) {
				t.Fatal("receipt completion lost exact native state or retained evidence")
			}
			if _, err := os.Lstat(filepath.Join(stage, "manifest.json")); err != nil {
				t.Fatal("receipt completion removed the original manifest", err)
			}
		})
	}
}

func TestRemovalRecoveryReceiptCompletionPreservesChangedOrUnconfirmedEvidence(t *testing.T) {
	for _, kind := range []string{"payload", "changed-review", "receipt-replaced", "orphan-replaced", "new-source", "native-error", "forget-failed", "forget-partial", "native-retained", "not-quiet", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			phase := "present"
			if kind == "payload" {
				phase = "payload"
			}
			if kind == "orphan-replaced" {
				phase = "plist-only"
			}
			f, files, stage := ownedRecoveryCompletionFixture(t, phase)
			if kind == "changed-review" {
				files.digest = "invalid"
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			read := ownedCurrentRecoveryReceiptReader(f)
			calls, forgot := 0, 0
			_, err := completeRemovalRecoveryReceipts(ctx, f.root, uint32(os.Geteuid()), files, removalRecoveryReceiptBackend{
				read: func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
					calls++
					if kind == "native-error" {
						return ErrRemoval
					}
					if calls == 1 {
						if kind == "receipt-replaced" || kind == "orphan-replaced" {
							f.write(removalReceipt+".plist", []byte("unknown replacement receipt"), 0600)
						}
						if kind == "new-source" {
							f.write(removalApp+"/keep", []byte("unknown replacement package"), 0600)
						}
					}
					return read(ctx, path, args, limit, consume)
				},
				forget: func(context.Context) error {
					forgot++
					if kind == "forget-failed" {
						return ErrRemoval
					}
					if kind == "forget-partial" {
						f.must(os.Remove(filepath.Join(f.root, removalReceipt+".plist")))
						return nil
					}
					if kind == "native-retained" {
						return nil
					}
					t.Fatal("unreviewed or cancelled receipt reached native mutation")
					return ErrRemoval
				},
				quiescent: func(context.Context) error {
					if kind == "not-quiet" {
						return ErrRemoval
					}
					if kind == "cancelled" {
						cancel()
					}
					return nil
				},
			})
			if err == nil {
				t.Fatal("changed or unconfirmed receipt acquired completion")
			}
			if kind == "receipt-replaced" || kind == "orphan-replaced" {
				data, err := os.ReadFile(filepath.Join(f.root, removalReceipt+".plist"))
				if err != nil || string(data) != "unknown replacement receipt" || forgot != 0 {
					t.Fatal("unknown receipt was deleted or forgotten", err)
				}
			}
			if _, err := os.Lstat(filepath.Join(stage, "manifest.json")); err != nil {
				t.Fatal("failed receipt completion removed staging evidence", err)
			}
		})
	}
}

func TestRemovalRecoveryFinishesOnlyExactEmptyScaffoldsAndManifest(t *testing.T) {
	for _, phase := range []string{"absent", "partial-scaffold"} {
		t.Run(phase, func(t *testing.T) {
			f, files, stage := ownedRecoveryCompletionFixture(t, phase)
			quiet := 0
			f.must(finishRemovalRecoveryStage(t.Context(), f.root, uint32(os.Geteuid()), files, ownedCurrentRecoveryReceiptReader(f), func(context.Context) error { quiet++; return nil }))
			if _, err := os.Lstat(stage); !os.IsNotExist(err) || quiet != 5 {
				t.Fatal("stage completion lost bounded repeated native absence", err, quiet)
			}
			f.must(removalSourcesAbsent(t.Context(), f.root, uint32(os.Geteuid()), true))
		})
	}
}

func TestRemovalRecoveryFinishPreservesUnexpectedEntriesAndUnconfirmedAbsence(t *testing.T) {
	for _, kind := range []string{"payload", "receipt", "changed-review", "unknown-root", "unknown-scaffold", "replaced-manifest", "new-source", "query-error", "not-quiet", "cancelled", "final-query-failure"} {
		t.Run(kind, func(t *testing.T) {
			phase := "absent"
			if kind == "payload" {
				phase = "payload"
			}
			if kind == "receipt" {
				phase = "present"
			}
			f, files, stage := ownedRecoveryCompletionFixture(t, phase)
			if kind == "changed-review" {
				files.digest = "invalid"
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			read := ownedCurrentRecoveryReceiptReader(f)
			calls := 0
			preserved := ""
			err := finishRemovalRecoveryStage(ctx, f.root, uint32(os.Geteuid()), files, func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
				calls++
				if kind == "query-error" || kind == "final-query-failure" && calls == 4 {
					return ErrRemoval
				}
				if calls == 1 {
					switch kind {
					case "unknown-root":
						preserved = filepath.Join(stage, "keep")
					case "unknown-scaffold":
						preserved = filepath.Join(stage, "Library/LaunchDaemons/keep")
					case "replaced-manifest":
						preserved = filepath.Join(stage, "manifest.json")
					case "new-source":
						f.write(removalApp+"/keep", []byte("unknown source"), 0600)
						preserved = filepath.Join(f.root, removalApp, "keep")
					}
					if preserved != "" && kind != "new-source" {
						f.must(os.WriteFile(preserved, []byte("unknown retained object"), 0600))
					}
				}
				return read(ctx, path, args, limit, consume)
			}, func(context.Context) error {
				if kind == "not-quiet" {
					return ErrRemoval
				}
				if kind == "cancelled" {
					cancel()
				}
				return nil
			})
			if err == nil {
				t.Fatal("incomplete absence or unknown staging acquired completion")
			}
			if preserved != "" {
				if _, err := os.Lstat(preserved); err != nil {
					t.Fatal("unknown object was deleted", err)
				}
			}
			if kind != "final-query-failure" {
				if _, err := os.Lstat(filepath.Join(stage, "manifest.json")); err != nil {
					t.Fatal("original evidence was removed before confirmed empty staging", err)
				}
			}
		})
	}
}
