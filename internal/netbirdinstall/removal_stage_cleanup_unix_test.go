//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
)

func ownedStageCleanupFixture(t *testing.T, kind string) (*removalFilesFixture, removalAbsenceBackend, string) {
	t.Helper()
	f, backend := ownedAbsenceFixture(t, true)
	stage := filepath.Join(f.root, "Applications", removalStagePrefix+ownedRemovalRequest)
	f.must(os.Mkdir(stage, 0700))
	if kind != "empty-stage" {
		for _, name := range removalStageParents[1:] {
			f.must(os.Mkdir(filepath.Join(stage, name), 0700))
		}
	}
	if kind == "empty-manifest" || kind == "incomplete-manifest" {
		data := []byte{}
		if kind == "incomplete-manifest" {
			data = []byte(`{"Schema":1,"RequestID":"` + ownedRemovalRequest)
		}
		f.must(os.WriteFile(filepath.Join(stage, "manifest.json"), data, 0600))
	}
	if kind == "partial-scaffold" {
		f.must(os.Remove(filepath.Join(stage, "Library/LaunchDaemons")))
		f.must(os.Remove(filepath.Join(stage, "Library")))
	}
	return f, backend, stage
}

func TestRemovalStageCleanupReviewsExactCurrentScaffoldAndPreservesHistory(t *testing.T) {
	for _, kind := range []string{"empty-stage", "missing-manifest", "empty-manifest", "incomplete-manifest", "partial-scaffold"} {
		t.Run(kind, func(t *testing.T) {
			f, backend, stage := ownedStageCleanupFixture(t, kind)
			owner := uint32(os.Geteuid())
			var held []*os.File
			v, err := inspectRemovalStageCleanup(t.Context(), f.root, owner, ownedRemovalRequest, backend, &held)
			defer func() {
				for _, file := range held {
					_ = file.Close()
				}
			}()
			f.must(err)
			if !netbirdcommand.ValidDigest(v.digest) || len(held) == 0 || v.directories < 1 {
				t.Fatal("cleanup review lost owned evidence")
			}
			if v.manifestPresent != (kind == "empty-manifest" || kind == "incomplete-manifest") {
				t.Fatal("cleanup review lost manifest presence")
			}
			again, err := inspectRemovalStageCleanup(t.Context(), f.root, owner, ownedRemovalRequest, backend, nil)
			f.must(err)
			if !reflect.DeepEqual(v, again) {
				t.Fatal("unchanged cleanup review drifted")
			}
			if data, err := json.Marshal(v); err == nil || len(data) != 0 || strings.Contains(fmt.Sprintf("%#v", v), f.root) {
				t.Fatal("private scaffold evidence escaped")
			}
			acquired, err := prepareRemovalStageCleanup(t.Context(), f.root, owner, ownedRemovalRequest, v.review(), backend)
			f.must(err)
			defer acquired.Close()
			if _, err := os.Stat(stage); err != nil {
				t.Fatal("preparation deleted the scaffold")
			}
			if _, err := inspectRemovalAbsence(t.Context(), f.root, owner, backend, nil); err == nil {
				t.Fatal("review or preparation silently cleared absence barrier")
			}
			f.must(acquired.Run(t.Context()))
			if _, err := os.Lstat(stage); !os.IsNotExist(err) {
				t.Fatal("reviewed scaffold remained", err)
			}
			if err := acquired.Run(t.Context()); err == nil {
				t.Fatal("cleanup owner ran twice")
			}
			f.must(acquired.Close())
			for _, file := range held {
				if _, err := file.Stat(); err != nil {
					t.Fatal("independent review descriptor closed prematurely")
				}
			}
			if _, err := inspectRemovalAbsence(t.Context(), f.root, owner, backend, nil); err != nil {
				t.Fatal("cleanup did not establish current absence", err)
			}
		})
	}
}

func TestRemovalStageCleanupRefusesUnknownPayloadAndUnsafeMetadata(t *testing.T) {
	for _, kind := range []string{"unknown-file", "unknown-directory", "payload", "foreign-stage", "malformed-stage", "manifest-symlink", "manifest-hardlink", "manifest-directory", "oversized-manifest", "unsafe-stage", "unsafe-scaffold", "unsafe-manifest", "stage-symlink", "missing-stage", "replacement-source", "receipt", "complete-manifest"} {
		t.Run(kind, func(t *testing.T) {
			f, backend, stage := ownedStageCleanupFixture(t, "missing-manifest")
			guard := ""
			switch kind {
			case "unknown-file":
				guard = filepath.Join(stage, "unknown")
				f.must(os.WriteFile(guard, []byte("preserve"), 0600))
			case "unknown-directory":
				guard = filepath.Join(stage, "unknown")
				f.must(os.Mkdir(guard, 0700))
			case "payload":
				guard = filepath.Join(stage, "Applications/NetBird.app")
				f.must(os.Mkdir(guard, 0700))
			case "foreign-stage", "malformed-stage":
				name := removalStagePrefix + "unknown"
				if kind == "foreign-stage" {
					name = removalStagePrefix + "60000000-0000-4000-8000-000000000006"
				}
				guard = filepath.Join(f.root, "Applications", name)
				f.must(os.Mkdir(guard, 0700))
			case "manifest-symlink":
				guard = filepath.Join(stage, "manifest.json")
				f.must(os.Symlink("/does-not-exist", guard))
			case "manifest-hardlink":
				guard = filepath.Join(f.root, "keep-metadata")
				f.must(os.WriteFile(guard, []byte("preserve"), 0600))
				f.must(os.Link(guard, filepath.Join(stage, "manifest.json")))
			case "manifest-directory":
				guard = filepath.Join(stage, "manifest.json")
				f.must(os.Mkdir(guard, 0700))
			case "oversized-manifest":
				guard = filepath.Join(stage, "manifest.json")
				f.must(os.WriteFile(guard, make([]byte, maxRemovalManifestBytes+1), 0600))
			case "unsafe-stage":
				guard = stage
				f.must(os.Chmod(guard, 0755))
			case "unsafe-scaffold":
				guard = filepath.Join(stage, "usr/local")
				f.must(os.Chmod(guard, 0755))
			case "unsafe-manifest":
				guard = filepath.Join(stage, "manifest.json")
				f.must(os.WriteFile(guard, []byte("incomplete"), 0644))
			case "stage-symlink":
				guard = stage + "-preserved"
				f.must(os.Rename(stage, guard))
				f.must(os.Symlink(guard, stage))
			case "missing-stage":
				guard = filepath.Join(f.root, "preserved")
				f.must(os.Rename(stage, guard))
			case "replacement-source":
				guard = filepath.Join(f.root, removalApp)
				f.must(os.Mkdir(guard, 0755))
			case "receipt":
				guard = filepath.Join(f.root, removalReceipt+".plist")
				f.must(os.WriteFile(guard, []byte("receipt"), 0644))
			case "complete-manifest":
				_, _, originalStage := ownedRecoveryCompletionFixture(t, "absent")
				data, err := os.ReadFile(filepath.Join(originalStage, "manifest.json"))
				f.must(err)
				guard = filepath.Join(stage, "manifest.json")
				f.must(os.WriteFile(guard, data, 0600))
			}
			if _, err := inspectRemovalStageCleanup(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, backend, nil); err == nil {
				t.Fatal("unsafe cleanup became eligible")
			}
			if _, err := os.Lstat(guard); err != nil {
				t.Fatal("refused cleanup changed retained evidence", err)
			}
		})
	}
}

func TestRemovalStageCleanupRejectsChangedReviewAndLateNativeEvidence(t *testing.T) {
	for _, kind := range []string{"digest", "summary", "original", "parent", "ancestry", "manifest", "unknown-after-review", "late-process", "late-receipt", "late-child", "partial-mutation", "final-query"} {
		t.Run(kind, func(t *testing.T) {
			f, backend, stage := ownedStageCleanupFixture(t, "incomplete-manifest")
			owner := uint32(os.Geteuid())
			v, err := inspectRemovalStageCleanup(t.Context(), f.root, owner, ownedRemovalRequest, backend, nil)
			f.must(err)
			if kind == "digest" || kind == "original" || kind == "summary" {
				id, review := ownedRemovalRequest, v.review()
				if kind == "digest" {
					review.StateDigest = strings.Repeat("e", 64)
				} else if kind == "summary" {
					review.ManifestBytes++
				} else {
					id = "60000000-0000-4000-8000-000000000006"
				}
				acquired, err := prepareRemovalStageCleanup(t.Context(), f.root, owner, id, review, backend)
				if err == nil || acquired != nil {
					if acquired != nil {
						_ = acquired.Close()
					}
					t.Fatal("changed review acquired cleanup")
				}
				return
			}
			active := false
			calls := 0
			read, quiet := backend.read, backend.quiet
			backend.quiet = func(ctx context.Context, selected string) error {
				if active {
					calls++
					if kind == "late-process" {
						return ErrRemoval
					}
				}
				return quiet(ctx, selected)
			}
			backend.read = func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
				if active {
					if kind == "late-receipt" || kind == "final-query" && calls == 17 {
						return ErrRemoval
					}
					if kind == "late-child" && calls == 2 || kind == "partial-mutation" && calls == 3 {
						f.must(os.WriteFile(filepath.Join(stage, "unknown"), []byte("preserve"), 0600))
					}
				}
				return read(ctx, path, args, limit, consume)
			}
			acquired, err := prepareRemovalStageCleanup(t.Context(), f.root, owner, ownedRemovalRequest, v.review(), backend)
			f.must(err)
			defer acquired.Close()
			switch kind {
			case "parent":
				f.must(os.Rename(stage, filepath.Join(f.root, "retained-stage")))
				f.must(os.Mkdir(stage, 0700))
			case "ancestry":
				f.must(os.Rename(filepath.Join(f.root, "Applications"), filepath.Join(f.root, "retained-applications")))
				f.must(os.Mkdir(filepath.Join(f.root, "Applications"), 0755))
				f.must(os.Rename(filepath.Join(f.root, "retained-applications", removalStagePrefix+ownedRemovalRequest), stage))
			case "manifest":
				f.must(os.WriteFile(filepath.Join(stage, "manifest.json"), []byte("changed metadata"), 0600))
			case "unknown-after-review":
				f.must(os.WriteFile(filepath.Join(stage, "unknown"), []byte("preserve"), 0600))
			}
			active = true
			if err := acquired.Run(t.Context()); err == nil {
				t.Fatal("changed or incomplete cleanup confirmed", kind, calls)
			}
			if kind == "final-query" {
				if _, err := os.Lstat(stage); !os.IsNotExist(err) {
					t.Fatal("fixture did not reach post-cleanup query", calls, err)
				}
			} else if _, err := os.Lstat(stage); err != nil {
				t.Fatal("unsafe cleanup removed stage", err)
			}
			if strings.Contains(kind, "child") || kind == "partial-mutation" || kind == "unknown-after-review" {
				data, err := os.ReadFile(filepath.Join(stage, "unknown"))
				f.must(err)
				if string(data) != "preserve" {
					t.Fatal("cleanup changed an unknown child")
				}
			}
		})
	}
}

func TestRemovalStageCleanupCloseJoinsCancelledRun(t *testing.T) {
	f, backend, stage := ownedStageCleanupFixture(t, "empty-stage")
	owner := uint32(os.Geteuid())
	v, err := inspectRemovalStageCleanup(t.Context(), f.root, owner, ownedRemovalRequest, backend, nil)
	f.must(err)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	active := false
	quiet := backend.quiet
	backend.quiet = func(ctx context.Context, path string) error {
		if active {
			once.Do(func() { close(entered) })
			<-release
			return ErrRemoval
		}
		return quiet(ctx, path)
	}
	acquired, err := prepareRemovalStageCleanup(t.Context(), f.root, owner, ownedRemovalRequest, v.review(), backend)
	f.must(err)
	active = true
	run, closed := make(chan error, 1), make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { run <- acquired.Run(ctx) }()
	<-entered
	cancel()
	go func() { closed <- acquired.Close() }()
	select {
	case <-closed:
		close(release)
		t.Fatal("close abandoned active cleanup")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-run; err == nil {
		t.Fatal("interrupted cleanup succeeded")
	}
	f.must(<-closed)
	if _, err := os.Stat(stage); err != nil {
		t.Fatal("close removed retained scaffold")
	}
}
