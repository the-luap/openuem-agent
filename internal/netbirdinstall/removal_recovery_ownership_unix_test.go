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

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

func TestRemovalRecoveryOwnershipRetainsAndClosesFirstRoundDescriptors(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			original, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
			f.must(err)
			defer stage.close()
			backend := ownedRecoveryOwnershipBackend(f, original.descriptor, "present", ownedRecoveryProcessBackend(nil))
			files := backend.files
			var retained []*os.File
			calls := 0
			backend.files = func(ctx context.Context, held *[]*os.File) (*removalRecoveryFiles, error) {
				calls++
				if calls == 2 {
					if held != nil || len(retained) == 0 {
						t.Fatal("first-round descriptor ownership missing")
					}
					for _, file := range retained {
						if _, err := file.Stat(); err != nil {
							t.Fatal("descriptor closed before complete repeated observation", err)
						}
					}
					if fail {
						return nil, ErrRemoval
					}
				}
				v, err := files(ctx, held)
				if calls == 1 && held != nil {
					retained = append([]*os.File(nil), (*held)...)
				}
				return v, err
			}
			_, err = inspectRemovalRecoveryOwnership(t.Context(), ownedRemovalRequest, original.descriptor, backend)
			if (err != nil) != fail || calls != 2 || len(retained) == 0 {
				t.Fatal("combined observation did not join descriptor lifetime", err)
			}
			for _, file := range retained {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("combined observation leaked an owned descriptor", err)
				}
			}
		})
	}
}

func ownedRecoveryReceiptReader(f *removalFilesFixture, phase string) packageReader {
	return func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
		if path != "/usr/sbin/pkgutil" || len(args) < 3 || args[0] != "--volume" || args[1] != "/" {
			f.t.Fatal("unexpected native receipt query")
		}
		var data string
		switch args[2] {
		case "--pkgs-plist":
			if len(args) != 3 || limit != maxRemovalReceiptList {
				f.t.Fatal("unbounded package list")
			}
			data = `<plist version="1.0"><array/></plist>`
			if phase == "present" || phase == "bom-only" {
				data = `<plist version="1.0"><array><string>io.netbird.client</string></array></plist>`
			}
		case "--pkg-info-plist":
			if phase != "present" || len(args) != 4 || args[3] != "io.netbird.client" || limit != 32<<10 {
				f.t.Fatal("partial receipt acquired a native version or unbounded query")
			}
			data = f.receipt
		case "--files":
			if phase != "present" && phase != "bom-only" || len(args) != 4 || args[3] != "io.netbird.client" || limit != 128<<10 {
				f.t.Fatal("missing BOM acquired native paths or unbounded query")
			}
			data = f.paths
		default:
			f.t.Fatal("receipt inspection attempted a native mutation")
		}
		return consume(strings.NewReader(data))
	}
}

func ownedRecoveryOwnershipBackend(f *removalFilesFixture, descriptor packageapi.Removal, phase string, processes removalProcessBackend) removalRecoveryOwnershipBackend {
	return removalRecoveryOwnershipBackend{
		files: func(ctx context.Context, held *[]*os.File) (*removalRecoveryFiles, error) {
			return inspectRemovalRecoveryFilesHeld(ctx, f.root, uint32(os.Geteuid()), ownedRemovalRequest, descriptor, held)
		},
		processes: func(ctx context.Context) (*removalRecoveryProcesses, error) {
			return inspectRemovalRecoveryProcesses(ctx, ownedRemovalRequest, processes)
		},
		job:  func(context.Context) ([]byte, bool, error) { return nil, false, nil },
		read: ownedRecoveryReceiptReader(f, phase),
	}
}

func TestRemovalRecoveryOwnershipBindsCompleteCurrentRuntimeAndReceiptState(t *testing.T) {
	for _, phase := range []string{"before-move", "loaded-original", "loaded-staged", "loaded-waiting", "partial-purge", "bom-only", "plist-only", "absent"} {
		t.Run(phase, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			original, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
			f.must(err)
			defer stage.close()
			if phase != "before-move" && phase != "loaded-original" {
				f.must(stage.move(t.Context()))
			}
			if phase == "partial-purge" {
				f.must(os.Remove(filepath.Join(stage.path, removalApp, "Contents/MacOS/netbird-ui")))
			}
			receiptKind := "present"
			if phase == "bom-only" || phase == "plist-only" || phase == "absent" {
				receiptKind = phase
				f.must(stage.purge(t.Context()))
				if phase != "plist-only" {
					f.must(os.Remove(filepath.Join(f.root, removalReceipt+".plist")))
				}
				if phase != "bom-only" {
					f.must(os.Remove(filepath.Join(f.root, removalReceipt+".bom")))
				}
			}
			f.must(stage.close())
			paths := map[int]string{}
			if phase == "loaded-original" {
				paths[45] = removalCLIExecutable
			}
			if phase == "loaded-staged" {
				paths[45] = "/Applications/" + removalStagePrefix + ownedRemovalRequest + removalCLIExecutable
			}
			backend := ownedRecoveryOwnershipBackend(f, original.descriptor, receiptKind, ownedRecoveryProcessBackend(paths))
			if strings.HasPrefix(phase, "loaded-") {
				backend.job = func(context.Context) ([]byte, bool, error) {
					data := ownedRemovalJob
					if phase == "loaded-waiting" {
						data = strings.Replace(data, "<key>PID</key><integer>45</integer>", "", 1)
					}
					return []byte(data), true, nil
				}
			}
			first, err := inspectRemovalRecoveryOwnership(t.Context(), ownedRemovalRequest, original.descriptor, backend)
			f.must(err)
			second, err := inspectRemovalRecoveryOwnership(t.Context(), ownedRemovalRequest, original.descriptor, backend)
			f.must(err)
			if len(first.digest) != 64 || first.digest != second.digest || first.receipts.kind != receiptKind || first.files.manifest.manifest.Descriptor != original.descriptor {
				t.Fatal("stable current evidence lost original/runtime/receipt binding")
			}
			for _, value := range []any{first, first.receipts} {
				if _, err := json.Marshal(value); err == nil {
					t.Fatal("private recovery ownership serialized")
				}
				if rendered := fmt.Sprintf("%+v %#v", value, value); strings.Contains(rendered, first.digest) || strings.Contains(rendered, ownedRemovalRequest) || strings.Contains(rendered, "Applications") {
					t.Fatal("private recovery ownership escaped")
				}
			}
			if removalNoStages(t.Context(), f.root, uint32(os.Geteuid())) == nil {
				t.Fatal("read-only runtime evidence removed retained staging")
			}
		})
	}
}

func TestRemovalRecoveryOwnershipRejectsChangedForeignOrIncompleteEvidence(t *testing.T) {
	for _, kind := range []string{"files-changed", "source-replaced", "receipt-replaced", "files-unavailable", "foreign-original", "foreign-descriptor", "processes-unavailable", "foreign-process-request", "changed-process", "job-unavailable", "changed-job", "foreign-daemon-user", "foreign-daemon-real-user", "ui-daemon", "missing-daemon", "staged-job-program", "query-failure", "query-contradiction", "query-changed", "wrong-version", "wrong-volume", "wrong-paths", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			original, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
			f.must(err)
			defer stage.close()
			f.must(stage.move(t.Context()))
			f.must(stage.close())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			path := "/Applications/" + removalStagePrefix + ownedRemovalRequest + removalCLIExecutable
			processBackend := ownedRecoveryProcessBackend(map[int]string{45: path})
			processBackend.inspect = func(ctx context.Context, pid int, path string) (removalProcess, error) {
				p := ownedRemovalProcess(uint32(pid), path)
				if kind == "foreign-daemon-user" {
					p.Audit[1] = 501
				}
				if kind == "foreign-daemon-real-user" {
					p.Audit[3] = 501
				}
				return p, nil
			}
			if kind == "ui-daemon" {
				processBackend = ownedRecoveryProcessBackend(map[int]string{45: removalUIExecutable})
			}
			if kind == "missing-daemon" {
				processBackend = ownedRecoveryProcessBackend(nil)
			}
			backend := ownedRecoveryOwnershipBackend(f, original.descriptor, "present", processBackend)
			files, processes, read := backend.files, backend.processes, backend.read
			fileCalls, processCalls, jobCalls, listCalls := 0, 0, 0, 0
			backend.files = func(ctx context.Context, held *[]*os.File) (*removalRecoveryFiles, error) {
				fileCalls++
				if kind == "files-unavailable" {
					return nil, ErrRemoval
				}
				v, err := files(ctx, held)
				if err != nil {
					return nil, err
				}
				if kind == "foreign-original" {
					v.manifest.manifest.RequestID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
				}
				if kind == "foreign-descriptor" {
					v.manifest.manifest.Descriptor.Version = "9.9.9"
				}
				if kind == "files-changed" && fileCalls == 2 {
					v.digest = strings.Repeat("e", 64)
				}
				return v, nil
			}
			backend.processes = func(ctx context.Context) (*removalRecoveryProcesses, error) {
				processCalls++
				if kind == "processes-unavailable" {
					return nil, errRemovalProcesses
				}
				v, err := processes(ctx)
				if err != nil {
					return nil, err
				}
				if kind == "foreign-process-request" {
					v.requestID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
				}
				if kind == "changed-process" && processCalls == 2 {
					v.processes[0].Audit[7]++
				}
				return v, nil
			}
			backend.job = func(context.Context) ([]byte, bool, error) {
				jobCalls++
				if kind == "job-unavailable" {
					return nil, false, ErrRemoval
				}
				data := ownedRemovalJob
				if kind == "changed-job" && jobCalls == 2 {
					data = strings.Replace(data, "info", "debug", 1)
				}
				if kind == "staged-job-program" {
					data = strings.ReplaceAll(data, "/usr/local/bin/netbird", path)
				}
				return []byte(data), true, nil
			}
			backend.read = func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
				if kind == "query-failure" {
					return ErrRemoval
				}
				if kind == "cancelled" {
					cancel()
				}
				if kind == "wrong-version" {
					f.receipt = strings.ReplaceAll(ownedReceipt, "0.78.1", "9.9.9")
				}
				if kind == "wrong-volume" {
					f.receipt = strings.ReplaceAll(ownedReceipt, "<string>/</string>", "<string>/owned-other-volume</string>")
				}
				if kind == "wrong-paths" {
					f.paths += "Applications/NetBird.app/unowned\n"
				}
				if args[2] == "--pkgs-plist" {
					listCalls++
					if kind == "query-contradiction" || kind == "query-changed" && listCalls == 2 {
						return consume(strings.NewReader(`<plist version="1.0"><array/></plist>`))
					}
					if listCalls == 1 && kind == "source-replaced" {
						f.write(removalApp+"/keep", []byte("unreviewed replacement"), 0600)
					}
					if listCalls == 1 && kind == "receipt-replaced" {
						f.write(removalReceipt+".plist", []byte("unreviewed receipt"), 0644)
					}
				}
				return read(ctx, path, args, limit, consume)
			}
			if v, err := inspectRemovalRecoveryOwnership(ctx, ownedRemovalRequest, original.descriptor, backend); err != ErrRemoval || v != nil {
				t.Fatal("changed or incomplete current ownership became recovery evidence", err)
			}
			if _, err := os.Lstat(stage.path); err != nil {
				t.Fatal("failed inspection removed retained staging", err)
			}
		})
	}
}

func TestRemovalRecoveryReceiptPartialStateMustAgreeWithNativeDatabase(t *testing.T) {
	for _, phase := range []string{"bom-only", "plist-only", "absent"} {
		t.Run(phase, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			original, err := ownedRemovalObserver(f)(t.Context())
			f.must(err)
			stage, err := newRemovalStaging(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original)
			f.must(err)
			defer stage.close()
			if phase != "plist-only" {
				f.must(os.Remove(filepath.Join(f.root, removalReceipt+".plist")))
			}
			if phase != "bom-only" {
				f.must(os.Remove(filepath.Join(f.root, removalReceipt+".bom")))
			}
			files, err := inspectRemovalRecoveryFiles(t.Context(), f.root, uint32(os.Geteuid()), ownedRemovalRequest, original.descriptor)
			f.must(err)
			calls := 0
			read := func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
				calls++
				if !reflect.DeepEqual(args, []string{"--volume", "/", "--pkgs-plist"}) {
					t.Fatal("contradictory native listing reached additional receipt commands")
				}
				data := `<plist version="1.0"><array><string>io.netbird.client</string></array></plist>`
				if phase == "bom-only" {
					data = `<plist version="1.0"><array/></plist>`
				}
				return consume(strings.NewReader(data))
			}
			if v, err := inspectRemovalRecoveryReceipts(t.Context(), files, read); err != ErrRemoval || v != nil || calls != 1 {
				t.Fatal("native database contradicted remaining original receipts", err)
			}
		})
	}
}
