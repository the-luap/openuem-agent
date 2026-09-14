//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const ownedRemovalRequest = "f34c0274-b8d1-4c70-8d45-775298dcad43"

func ownedRemovalObserver(f *removalFilesFixture) func(context.Context) (*removalOwnership, error) {
	return func(ctx context.Context) (*removalOwnership, error) {
		return inspectRemovalOwnership(ctx, removalOwnershipBackend{files: f.inspect, processes: func(context.Context) (*removalProcessEvidence, error) {
			return &removalProcessEvidence{digest: strings.Repeat("b", 64)}, nil
		}, job: func(context.Context) ([]byte, bool, error) { return nil, false, nil }})
	}
}

func ownedRemovalBackend(f *removalFilesFixture, events *[]string) removalExecutionBackend {
	return removalExecutionBackend{
		observe:   ownedRemovalObserver(f),
		stop:      func(context.Context, *removalOwnership) error { *events = append(*events, "stop"); return nil },
		quiescent: func(context.Context, string) error { *events = append(*events, "quiet"); return nil },
		forget: func(context.Context) error {
			*events = append(*events, "forget")
			for _, suffix := range []string{".plist", ".bom"} {
				if os.Remove(filepath.Join(f.root, removalReceipt+suffix)) != nil {
					return ErrRemoval
				}
			}
			return nil
		},
		absent: func(ctx context.Context) error {
			*events = append(*events, "absent")
			return removalSourcesAbsent(ctx, f.root, uint32(os.Geteuid()), true)
		},
	}
}

func TestRemovalExecutesOnlyOwnedFilesAndVerifiesAbsence(t *testing.T) {
	for _, optional := range []bool{false, true} {
		t.Run(fmt.Sprint(optional), func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			if optional {
				f.must(os.Remove(filepath.Join(f.root, removalCLI)))
				f.must(os.Remove(filepath.Join(f.root, removalDaemon)))
			}
			for _, name := range []string{"etc/netbird/config.json", "var/log/netbird/client.log", "Applications/Other.app/keep"} {
				f.write(name, []byte("owned retained data"), 0600)
			}
			var events []string
			backend := ownedRemovalBackend(f, &events)
			observed, err := backend.observe(t.Context())
			f.must(err)
			owner, err := prepareRemoval(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, observed.descriptor, backend)
			f.must(err)
			defer owner.Close()
			stage := filepath.Join(f.root, "Applications", removalStagePrefix+ownedRemovalRequest)
			if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) || len(events) != 0 {
				t.Fatal("preparation mutated the installation")
			}
			f.must(owner.Run(t.Context()))
			f.must(owner.Close())
			if !reflect.DeepEqual(events, []string{"stop", "quiet", "forget", "quiet", "absent"}) {
				t.Fatal("native ownership/result sequence changed", events)
			}
			if owner.Run(t.Context()) == nil {
				t.Fatal("removal owner executed twice")
			}
			if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("successful stage retained")
			}
			for _, name := range []string{"etc/netbird/config.json", "var/log/netbird/client.log", "Applications/Other.app/keep"} {
				data, err := os.ReadFile(filepath.Join(f.root, name))
				if err != nil || string(data) != "owned retained data" {
					t.Fatal("unowned state removed")
				}
			}
		})
	}
}

func TestRemovalRejectsChangedStateAndRetainsInterruptedStage(t *testing.T) {
	for _, kind := range []string{"review-changed", "source-replaced", "source-nested-change", "source-nested-extra", "stage-extra", "stage-content", "receipt-changed", "cancel-after-move", "still-running", "forget-failed", "receipt-retained", "new-source", "stage-root-extra", "final-query-failed"} {
		t.Run(kind, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			var events []string
			backend := ownedRemovalBackend(f, &events)
			observed, err := backend.observe(t.Context())
			f.must(err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stage := filepath.Join(f.root, "Applications", removalStagePrefix+ownedRemovalRequest)
			if kind == "source-replaced" {
				backend.stop = func(context.Context, *removalOwnership) error {
					f.must(os.Rename(filepath.Join(f.root, removalApp), filepath.Join(f.root, "Applications/Retained.app")))
					f.write(removalApp+"/keep", []byte("owned replacement"), 0600)
					return nil
				}
			}
			if kind == "source-nested-change" || kind == "source-nested-extra" {
				backend.stop = func(context.Context, *removalOwnership) error {
					name := removalApp + "/Contents/Resources/LICENSE"
					if kind == "source-nested-extra" {
						name = removalApp + "/Contents/Resources/keep"
					}
					f.write(name, []byte("owned later nested data"), 0644)
					return nil
				}
			}
			quiet := backend.quiescent
			backend.quiescent = func(ctx context.Context, path string) error {
				if path != filepath.Join(stage, removalApp) {
					t.Fatal("staged process path missing")
				}
				switch kind {
				case "stage-extra":
					f.must(os.WriteFile(filepath.Join(path, "Contents/unreviewed"), []byte("owned unexpected entry"), 0600))
				case "stage-content":
					f.must(os.WriteFile(filepath.Join(path, "Contents/Resources/LICENSE"), []byte("owned changed data"), 0600))
				case "receipt-changed":
					f.write(removalReceipt+".bom", []byte("owned changed receipt"), 0644)
				case "cancel-after-move":
					cancel()
				case "still-running":
					return ErrRemoval
				}
				return quiet(ctx, path)
			}
			forget := backend.forget
			if kind == "forget-failed" {
				backend.forget = func(context.Context) error { return ErrRemoval }
			}
			if kind == "receipt-retained" {
				backend.forget = func(context.Context) error { return nil }
			}
			if kind == "new-source" {
				backend.forget = func(ctx context.Context) error {
					if err := forget(ctx); err != nil {
						return err
					}
					f.write(removalApp+"/keep", []byte("owned later installation"), 0600)
					return nil
				}
			}
			if kind == "final-query-failed" {
				backend.absent = func(context.Context) error { return ErrRemoval }
			}
			if kind == "stage-root-extra" {
				backend.forget = func(ctx context.Context) error {
					f.must(os.WriteFile(filepath.Join(stage, "keep"), []byte("owned unexpected root entry"), 0600))
					return forget(ctx)
				}
			}
			owner, err := prepareRemoval(ctx, f.root, uint32(os.Geteuid()), ownedRemovalRequest, observed.descriptor, backend)
			f.must(err)
			if kind == "review-changed" {
				f.write(removalApp+"/Contents/Resources/LICENSE", []byte("owned later version"), 0644)
			}
			if owner.Run(ctx) != ErrRemoval {
				t.Fatal("uncertain removal reported success")
			}
			f.must(owner.Close())
			if owner.Run(t.Context()) == nil {
				t.Fatal("uncertain action retried")
			}
			if kind != "review-changed" && kind != "final-query-failed" {
				info, err := os.Stat(stage)
				if err != nil || info.Mode().Perm() != 0700 {
					t.Fatal("uncertain stage not preserved")
				}
				manifest, err := os.ReadFile(filepath.Join(stage, "manifest.json"))
				f.must(err)
				if strings.Contains(string(manifest), "owned-secret-service-value") {
					t.Fatal("service plaintext persisted")
				}
				if !strings.Contains(string(manifest), observed.descriptor.StateDigest) {
					t.Fatal("original review evidence missing")
				}
				if removalSourcesAbsent(t.Context(), f.root, uint32(os.Geteuid()), true) == nil {
					t.Fatal("retained partial stage treated as absent")
				}
			}
			if kind == "source-replaced" || kind == "new-source" {
				if _, err := os.Stat(filepath.Join(f.root, removalApp, "keep")); err != nil {
					t.Fatal("unowned replacement removed")
				}
			}
			if kind == "source-nested-change" || kind == "source-nested-extra" {
				name := removalApp + "/Contents/Resources/LICENSE"
				if kind == "source-nested-extra" {
					name = removalApp + "/Contents/Resources/keep"
				}
				data, err := os.ReadFile(filepath.Join(f.root, name))
				if err != nil || string(data) != "owned later nested data" {
					t.Fatal("unreviewed relocated subtree was not restored")
				}
				if _, err := os.Lstat(filepath.Join(stage, removalApp)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("restored source remained staged")
				}
			}
		})
	}
}

func TestRemovalRetainedStageRejectsFreshPreparationWithoutMutation(t *testing.T) {
	f := newRemovalFilesFixture(t)
	var events []string
	backend := ownedRemovalBackend(f, &events)
	observed, err := backend.observe(t.Context())
	f.must(err)
	stage := filepath.Join(f.root, "Applications", removalStagePrefix+ownedRemovalRequest)
	f.must(os.Mkdir(stage, 0700))
	f.must(os.WriteFile(filepath.Join(stage, "keep"), []byte("owned interrupted evidence"), 0600))
	owner, err := prepareRemoval(t.Context(), f.root, uint32(os.Geteuid()), "00f0a7f9-9a77-48e6-96ba-fc71a98a35e0", observed.descriptor, backend)
	if err != ErrRemoval || owner != nil || len(events) != 0 {
		t.Fatal("retained stage admitted fresh native work")
	}
	data, err := os.ReadFile(filepath.Join(stage, "keep"))
	f.must(err)
	if string(data) != "owned interrupted evidence" {
		t.Fatal("retained evidence changed")
	}
}

func TestRemovalStageRefusesOverwriteAndPreservesUnexpectedEntries(t *testing.T) {
	f := newRemovalFilesFixture(t)
	observed, err := ownedRemovalObserver(f)(t.Context())
	f.must(err)
	s, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, observed)
	f.must(err)
	defer s.close()
	f.must(os.Mkdir(filepath.Join(s.path, removalApp), 0700))
	f.must(os.WriteFile(filepath.Join(s.path, removalApp, "keep"), []byte("owned collision"), 0600))
	if s.move(t.Context()) == nil {
		t.Fatal("exclusive destination collision overwritten")
	}
	if _, err := os.Stat(filepath.Join(f.root, removalApp, "Contents")); err != nil {
		t.Fatal("source lost during collision")
	}
	if _, err := os.Stat(filepath.Join(s.path, removalApp, "keep")); err != nil {
		t.Fatal("unexpected destination lost")
	}
	if data, err := json.Marshal(s); err == nil || len(data) != 0 {
		t.Fatal("private stage serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", s), f.root) {
		t.Fatal("private stage exposed")
	}
}

func TestRemovalAbsenceRequiresProtectedPathsReceiptsAndNativeQueries(t *testing.T) {
	for _, kind := range []string{"absent", "missing-parents", "app", "cli", "daemon", "receipt", "retained-stage", "symlink-parent", "untrusted-parent", "query-error", "query-present", "query-whitespace", "running"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			f := &removalFilesFixture{t: t, root: root}
			f.must(os.Mkdir(filepath.Join(root, "Applications"), 0755))
			switch kind {
			case "app":
				f.write(removalApp+"/keep", nil, 0600)
			case "cli":
				f.write(removalCLI, nil, 0600)
			case "daemon":
				f.write(removalDaemon, nil, 0600)
			case "receipt":
				f.write(removalReceipt+".bom", nil, 0600)
			case "retained-stage":
				f.must(os.Mkdir(filepath.Join(root, "Applications", removalStagePrefix+ownedRemovalRequest), 0700))
			case "symlink-parent":
				f.must(os.Symlink(t.TempDir(), filepath.Join(root, "usr")))
			case "untrusted-parent":
				f.must(os.Mkdir(filepath.Join(root, "usr"), 0755))
				f.must(os.Chmod(filepath.Join(root, "usr"), 0777))
			case "missing-parents":
				f.must(os.Remove(filepath.Join(root, "Applications")))
			}
			queries, quiet := 0, 0
			err := verifyNativeRemovalAbsence(t.Context(), root, uint32(os.Geteuid()), func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
				queries++
				if path != "/usr/sbin/pkgutil" || !reflect.DeepEqual(args, []string{"--volume", "/", "--pkgs-plist"}) || limit != maxRemovalReceiptList {
					t.Fatal("unbounded or foreign receipt query")
				}
				if kind == "query-error" {
					return ErrRemoval
				}
				data := `<plist version="1.0"><array/></plist>`
				if kind == "query-present" {
					data = `<plist version="1.0"><array><string>io.netbird.client</string></array></plist>`
				}
				if kind == "query-whitespace" {
					data = "\n"
				}
				return consume(strings.NewReader(data))
			}, func(context.Context, string) error {
				quiet++
				if kind == "running" {
					return ErrRemoval
				}
				return nil
			})
			want := kind == "absent" || kind == "missing-parents"
			if (err == nil) != want || want && (queries != 2 || quiet != 2) {
				t.Fatal("incomplete native absence accepted", kind, err)
			}
		})
	}
}

func TestRemovalQuiescenceRequiresCompleteCandidateEnumeration(t *testing.T) {
	for _, kind := range []string{"quiet", "gone", "cli", "ui", "staged-cli", "staged-ui", "inaccessible", "missing-init", "duplicate", "overflow", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			staged := "/owned/stage/Applications/NetBird.app"
			err := removalNoProcesses(ctx, staged, func(context.Context) ([]int, error) {
				pids := []int{0, 1, 42}
				switch kind {
				case "missing-init":
					pids = []int{42}
				case "duplicate":
					pids = append(pids, 42)
				case "overflow":
					pids = make([]int, maxRemovalPIDs+1)
				}
				return pids, nil
			}, func(ctx context.Context, pid int) (string, error) {
				if pid != 42 {
					return "/sbin/launchd", nil
				}
				switch kind {
				case "gone":
					return "", errRemovalProcessGone
				case "cli":
					return removalCLIExecutable, nil
				case "ui":
					return removalUIExecutable, nil
				case "staged-cli":
					return staged + "/Contents/MacOS/netbird", nil
				case "staged-ui":
					return staged + "/Contents/MacOS/netbird-ui", nil
				case "inaccessible":
					return "", ErrRemoval
				}
				return "/owned/unrelated", nil
			})
			if (err == nil) != (kind == "quiet" || kind == "gone") {
				t.Fatal("incomplete process absence accepted", kind)
			}
		})
	}
}

func TestRemovalCloseJoinsRunAndPreservesCleanupFailure(t *testing.T) {
	started, finish, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r := &Removal{run: func(context.Context) error { close(started); <-finish; return nil }, close: func() error { close(closed); return ErrRemoval }}
	runResult := make(chan error, 1)
	go func() { runResult <- r.Run(t.Context()) }()
	<-started
	closeResult := make(chan error, 1)
	go func() { closeResult <- r.Close() }()
	select {
	case <-closed:
		t.Fatal("cleanup crossed native execution")
	case <-time.After(25 * time.Millisecond):
	}
	close(finish)
	if <-runResult != nil || <-closeResult != ErrRemoval || r.Close() != ErrRemoval {
		t.Fatal("cleanup result lost")
	}
	if data, err := json.Marshal(r); err == nil || len(data) != 0 {
		t.Fatal("native owner serialized")
	}
	if _, err := PrepareRemoval(t.Context(), "bad", packageapi.Removal{}); err != ErrRemoval {
		t.Fatal("invalid removal accepted")
	}
}
