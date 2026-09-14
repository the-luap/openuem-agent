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
	"testing"

	"github.com/open-uem/nats/netbirdcommand"
)

func ownedAbsenceFixture(t *testing.T, parents bool) (*removalFilesFixture, removalAbsenceBackend) {
	t.Helper()
	f := &removalFilesFixture{t: t, root: t.TempDir()}
	if parents {
		for _, name := range []string{"Applications", "usr/local/bin", "Library/LaunchDaemons", "private/var/db/receipts"} {
			f.must(os.MkdirAll(filepath.Join(f.root, name), 0755))
		}
	}
	backend := removalAbsenceBackend{
		read: func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
			if ctx.Err() != nil || path != "/usr/sbin/pkgutil" || !reflect.DeepEqual(args, []string{"--volume", "/", "--pkgs-plist"}) || limit != maxRemovalReceiptList {
				t.Fatal("absence used an unexpected native query")
			}
			return consume(strings.NewReader(`<plist version="1.0"><array/></plist>`))
		},
		quiet: func(ctx context.Context, staged string) error {
			if ctx.Err() != nil || staged != "" {
				t.Fatal("independent absence selected an original stage")
			}
			return nil
		},
	}
	return f, backend
}

func TestRemovalCurrentAbsenceBindsProtectedAncestryAndRetainsDescriptors(t *testing.T) {
	for _, parents := range []bool{false, true} {
		t.Run(fmt.Sprint(parents), func(t *testing.T) {
			f, backend := ownedAbsenceFixture(t, parents)
			var held []*os.File
			v, err := inspectRemovalAbsence(t.Context(), f.root, uint32(os.Geteuid()), backend, &held)
			defer func() {
				for _, file := range held {
					_ = file.Close()
				}
			}()
			if err != nil || !netbirdcommand.ValidDigest(v.digest) || len(held) == 0 {
				t.Fatal("absence lost current evidence", err)
			}
			for _, name := range []string{removalApp, removalCLI, removalDaemon, removalReceipt + ".bom", removalReceipt + ".plist"} {
				if !v.objects[name].Missing {
					t.Fatal("absence omitted supported layout", name)
				}
			}
			for _, file := range held {
				if _, err := file.Stat(); err != nil {
					t.Fatal("review descriptor closed early", err)
				}
			}
			again, err := inspectRemovalAbsence(t.Context(), f.root, uint32(os.Geteuid()), backend, nil)
			if err != nil || !reflect.DeepEqual(v, again) {
				t.Fatal("unchanged absence fingerprint drifted", err)
			}
			if data, err := json.Marshal(v); err == nil || len(data) != 0 || strings.Contains(fmt.Sprintf("%#v", v), f.root) {
				t.Fatal("private absence evidence escaped")
			}
			// No original manifest or descriptor is needed; replacement ancestry
			// still produces a different current review, even with all files absent.
			if parents {
				f.must(os.Rename(filepath.Join(f.root, "Applications"), filepath.Join(f.root, "previous-applications")))
			}
			f.must(os.Mkdir(filepath.Join(f.root, "Applications"), 0755))
			changed, err := inspectRemovalAbsence(t.Context(), f.root, uint32(os.Geteuid()), backend, nil)
			if err != nil || changed.digest == v.digest {
				t.Fatal("absence ignored changed ancestry", err)
			}
		})
	}
}

func TestRemovalCurrentAbsenceRefusesEveryRemainingLayoutAndStage(t *testing.T) {
	for _, kind := range []string{"app", "cli", "daemon", "bom", "plist", "empty-stage", "missing-manifest", "empty-manifest", "incomplete-manifest", "foreign-stage", "stage-symlink", "stage-file", "ancestor-symlink", "ancestor-file", "unsafe-parent"} {
		t.Run(kind, func(t *testing.T) {
			f, backend := ownedAbsenceFixture(t, true)
			path := ""
			switch kind {
			case "app":
				path = removalApp + "/keep"
			case "cli":
				path = removalCLI
			case "daemon":
				path = removalDaemon
			case "bom":
				path = removalReceipt + ".bom"
			case "plist":
				path = removalReceipt + ".plist"
			}
			if path != "" {
				f.write(path, []byte("preserved"), 0600)
			}
			if strings.Contains(kind, "stage") || strings.Contains(kind, "manifest") {
				path = "Applications/" + removalStagePrefix + ownedRemovalRequest
				if kind == "foreign-stage" {
					path = "Applications/" + removalStagePrefix + "unknown"
				}
				switch kind {
				case "stage-file":
					f.write(path, []byte("preserved"), 0600)
				case "stage-symlink":
					f.must(os.Symlink(t.TempDir(), filepath.Join(f.root, path)))
				default:
					f.must(os.Mkdir(filepath.Join(f.root, path), 0700))
					if kind == "missing-manifest" {
						f.write(path+"/keep", []byte("preserved"), 0600)
					}
					if kind == "empty-manifest" {
						f.write(path+"/manifest.json", nil, 0600)
					}
					if kind == "incomplete-manifest" {
						f.write(path+"/manifest.json", []byte(`{"schema":1`), 0600)
					}
				}
			}
			if strings.HasPrefix(kind, "ancestor-") {
				f.must(os.Rename(filepath.Join(f.root, "usr"), filepath.Join(f.root, "previous-usr")))
				path = "usr"
				if kind == "ancestor-symlink" {
					f.must(os.Symlink(filepath.Join(t.TempDir(), "missing"), filepath.Join(f.root, path)))
				} else {
					f.write(path, nil, 0600)
				}
			}
			if kind == "unsafe-parent" {
				path = "usr"
				f.must(os.Chmod(filepath.Join(f.root, path), 0777))
			}
			queries := 0
			backend.quiet = func(context.Context, string) error { queries++; return nil }
			if v, err := inspectRemovalAbsence(t.Context(), f.root, uint32(os.Geteuid()), backend, nil); err == nil || v != nil || queries != 0 {
				t.Fatal("remaining objects became absence")
			}
			if _, err := os.Lstat(filepath.Join(f.root, path)); err != nil {
				t.Fatal("read-only refusal removed retained object", err)
			}
		})
	}
}

func TestRemovalCurrentAbsenceRefusesChangesDuringNativeQueries(t *testing.T) {
	for _, kind := range []string{"app", "receipt", "stage", "replace-parent", "missing-parent", "late-unsafe-parent", "native-error", "native-present", "late-running", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			f, backend := ownedAbsenceFixture(t, true)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			read, quiet := backend.read, backend.quiet
			queries, scans := 0, 0
			backend.read = func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
				queries++
				if queries == 2 {
					switch kind {
					case "app":
						f.write(removalApp+"/keep", nil, 0600)
					case "receipt":
						f.write(removalReceipt+".plist", nil, 0600)
					case "stage":
						f.must(os.Mkdir(filepath.Join(f.root, "Applications", removalStagePrefix+ownedRemovalRequest), 0700))
					case "replace-parent":
						f.must(os.Rename(filepath.Join(f.root, "Applications"), filepath.Join(f.root, "previous-applications")))
						f.must(os.Mkdir(filepath.Join(f.root, "Applications"), 0755))
					case "missing-parent":
						f.must(os.Remove(filepath.Join(f.root, "Applications")))
					case "late-unsafe-parent":
						f.must(os.Chmod(filepath.Join(f.root, "Applications"), 0777))
					case "native-error":
						return ErrRemoval
					case "native-present":
						return consume(strings.NewReader(`<plist version="1.0"><array><string>io.netbird.client</string></array></plist>`))
					case "cancelled":
						cancel()
						return ErrRemoval
					}
				}
				return read(ctx, path, args, limit, consume)
			}
			backend.quiet = func(ctx context.Context, path string) error {
				scans++
				if scans == 2 && kind == "late-running" {
					return ErrRemoval
				}
				return quiet(ctx, path)
			}
			var held []*os.File
			if v, err := inspectRemovalAbsence(ctx, f.root, uint32(os.Geteuid()), backend, &held); err == nil || v != nil || len(held) != 0 {
				t.Fatal("changed current evidence became absence")
			}
		})
	}
}

func TestRemovalAbsenceOwnerRechecksCurrentReviewWithoutMutation(t *testing.T) {
	for _, kind := range []string{"verified", "changed-before-prepare", "changed-before-run", "wrong-review", "closed", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			f, backend := ownedAbsenceFixture(t, true)
			v, err := inspectRemovalAbsence(t.Context(), f.root, uint32(os.Geteuid()), backend, nil)
			f.must(err)
			if kind == "wrong-review" {
				v.digest = strings.Repeat("f", 64)
			}
			if kind == "changed-before-prepare" {
				f.write(removalCLI, []byte("preserved"), 0600)
			}
			owner, err := prepareRemovalAbsence(t.Context(), f.root, uint32(os.Geteuid()), v.digest, backend)
			if kind == "wrong-review" || kind == "changed-before-prepare" {
				if err == nil || owner != nil {
					t.Fatal("stale review acquired owner")
				}
				return
			}
			f.must(err)
			defer owner.Close()
			if kind == "changed-before-run" {
				f.write(removalCLI, []byte("preserved"), 0600)
			}
			if kind == "closed" {
				f.must(owner.Close())
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			if err := owner.Run(ctx); (err == nil) != (kind == "verified") {
				t.Fatal("verification ignored current review", err)
			}
			if kind != "cancelled" && owner.Run(t.Context()) == nil {
				t.Fatal("verification owner repeated")
			}
			f.must(owner.Close())
			f.must(owner.Close())
			if kind == "changed-before-run" {
				if data, err := os.ReadFile(filepath.Join(f.root, removalCLI)); err != nil || string(data) != "preserved" {
					t.Fatal("verification modified a replacement", err)
				}
			}
		})
	}
}

func TestRemovalAbsenceRefusesProcessesFromEveryRetainedStageNamespace(t *testing.T) {
	for _, path := range []string{
		"/Applications/" + removalStagePrefix + ownedRemovalRequest + removalCLIExecutable,
		"/Applications/" + removalStagePrefix + "ffffffff-ffff-4fff-8fff-ffffffffffff" + removalUIExecutable,
		"/Applications/" + removalStagePrefix + "incomplete/unknown-executable",
		"/Applications/" + removalStagePrefix + "/unknown-executable",
	} {
		t.Run(path, func(t *testing.T) {
			f, backend := ownedAbsenceFixture(t, false)
			backend.quiet = func(ctx context.Context, stage string) error {
				return removalNoProcesses(ctx, stage, func(context.Context) ([]int, error) { return []int{1, 42}, nil }, func(_ context.Context, pid int) (string, error) {
					if pid == 42 {
						return path, nil
					}
					return "/sbin/launchd", nil
				})
			}
			if v, err := inspectRemovalAbsence(t.Context(), f.root, uint32(os.Geteuid()), backend, nil); err == nil || v != nil {
				t.Fatal("deleted stage process became absence")
			}
		})
	}
}

func TestRemovalAbsenceRejectsInvalidAcquisition(t *testing.T) {
	f, backend := ownedAbsenceFixture(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, input := range []struct {
		ctx     context.Context
		root    string
		backend removalAbsenceBackend
	}{
		{nil, f.root, backend}, {ctx, f.root, backend}, {t.Context(), "relative", backend},
		{t.Context(), f.root + "/../alias", backend}, {t.Context(), f.root, removalAbsenceBackend{}},
		{t.Context(), f.root, removalAbsenceBackend{read: backend.read}},
		{t.Context(), f.root, removalAbsenceBackend{quiet: backend.quiet}},
	} {
		if v, err := inspectRemovalAbsence(input.ctx, input.root, uint32(os.Geteuid()), input.backend, nil); err == nil || v != nil {
			t.Fatal("invalid absence acquisition")
		}
	}
	if _, err := InspectRemovalAbsence(nil); err != ErrRemoval {
		t.Fatal("invalid native inspection")
	}
	if _, err := PrepareRemovalAbsence(nil, ""); err != ErrRemoval {
		t.Fatal("invalid native owner")
	}
}
