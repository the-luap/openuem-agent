//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const ownedRemovalInfo = `<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.netbird.client</string><key>CFBundleVersion</key><string>0.78.1</string><key>CFBundleShortVersionString</key><string>0.78.1</string><key>CFBundleExecutable</key><string>netbird-ui</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>`
const ownedRemovalService = `<plist version="1.0"><dict><key>Label</key><string>netbird</string><key>ProgramArguments</key><array><string>/usr/local/bin/netbird</string><string>service</string><string>run</string><string>--log-level</string><string>info</string></array><key>KeepAlive</key><true/><key>RunAtLoad</key><true/><key>EnvironmentVariables</key><dict><key>OWNED_PRIVATE_VALUE</key><string>owned-secret-service-value</string></dict></dict></plist>`

type removalFilesFixture struct {
	t                     *testing.T
	root, receipt, paths  string
	queries, signatures   int
	readErr, signatureErr error
	duringSignature       func()
}

func newRemovalFilesFixture(t *testing.T) *removalFilesFixture {
	t.Helper()
	if runtime.GOOS == "darwin" && !nativeInstallerAvailable() {
		t.Skip("native ACL support unavailable")
	}
	f := &removalFilesFixture{t: t, root: t.TempDir(), receipt: ownedReceipt}
	f.write(removalApp+"/Contents/Info.plist", []byte(ownedRemovalInfo), 0644)
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(header[4:8], 0x0100000c)
	binary.LittleEndian.PutUint32(header[12:16], 2)
	for _, name := range []string{"netbird", "netbird-ui"} {
		f.write(removalApp+"/Contents/MacOS/"+name, header, 0755)
	}
	f.write(removalApp+"/Contents/Resources/LICENSE", []byte("owned inert resource"), 0644)
	f.write(removalApp+"/Contents/_CodeSignature/CodeResources", []byte("owned inert signature metadata"), 0644)
	f.write(removalReceipt+".plist", []byte("owned inert package receipt"), 0644)
	f.write(removalReceipt+".bom", []byte("owned inert package file receipt"), 0644)
	f.write(removalDaemon, []byte(ownedRemovalService), 0644)
	f.must(os.MkdirAll(filepath.Join(f.root, filepath.Dir(removalCLI)), 0755))
	f.must(os.Symlink("/"+removalApp+"/Contents/MacOS/netbird", filepath.Join(f.root, removalCLI)))
	f.refreshPaths()
	return f
}

func (f *removalFilesFixture) must(err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *removalFilesFixture) write(name string, data []byte, mode os.FileMode) {
	f.t.Helper()
	path := filepath.Join(f.root, name)
	f.must(os.MkdirAll(filepath.Dir(path), 0755))
	f.must(os.WriteFile(path, data, mode))
}
func (f *removalFilesFixture) refreshPaths() {
	var names []string
	f.must(filepath.WalkDir(filepath.Join(f.root, "Applications"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name, err := filepath.Rel(f.root, path)
		if err != nil {
			return err
		}
		names = append(names, name)
		return nil
	}))
	f.paths = strings.Join(names, "\n") + "\n"
}
func (f *removalFilesFixture) inspect(ctx context.Context) (*removalFileEvidence, error) {
	return inspectRemovalFiles(ctx, f.root, uint32(os.Geteuid()), "arm64", removalFilesBackend{
		read: func(ctx context.Context, executable string, args []string, limit int64, consume func(io.Reader) error) error {
			f.queries++
			if executable != "/usr/sbin/pkgutil" || len(args) != 4 || args[0] != "--volume" || args[1] != "/" || args[3] != "io.netbird.client" {
				f.t.Fatal("unexpected native query")
			}
			if f.readErr != nil {
				return f.readErr
			}
			data := f.receipt
			if args[2] == "--files" {
				data = f.paths
			} else if args[2] != "--pkg-info-plist" {
				f.t.Fatal("unexpected native query operation")
			}
			return consume(strings.NewReader(data))
		},
		verify: func(ctx context.Context, root string) error {
			f.signatures++
			if root != f.root {
				f.t.Fatal("unexpected native verification root")
			}
			if f.duringSignature != nil {
				f.duringSignature()
			}
			return f.signatureErr
		},
	})
}

func TestRemovalFilesInspectExactOwnedPackageWithoutExposingPrivateEvidence(t *testing.T) {
	f := newRemovalFilesFixture(t)
	first, err := f.inspect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first.version != "0.78.1" || first.architecture != "arm64" || len(first.digest) != 64 || f.queries != 2 || f.signatures != 1 {
		t.Fatal("missing native ownership evidence")
	}
	for name := range first.objects {
		if strings.HasPrefix(name, removalApp+"/") && first.objects[name].Mode&uint32(os.ModeDir) == 0 {
			_, err := os.ReadFile(filepath.Join(f.root, name))
			f.must(err)
		}
	}
	again, err := f.inspect(t.Context())
	if err != nil || first.digest != again.digest {
		t.Fatal("ordinary reads changed the reviewed filesystem state", err)
	}
	for _, rendered := range []string{fmt.Sprint(first), fmt.Sprintf("%+v", first), fmt.Sprintf("%#v", first)} {
		if strings.Contains(rendered, f.root) || strings.Contains(rendered, "owned-secret") || strings.Contains(rendered, first.digest) {
			t.Fatal("private native evidence escaped")
		}
	}
	if data, err := json.Marshal(first); err == nil || len(data) != 0 {
		t.Fatal("private native evidence serialized")
	}
}

func TestRemovalFilesRejectAmbiguousChangedOrUnownedPackageObjects(t *testing.T) {
	cases := []string{"missing-receipt", "linked-receipt", "empty-info", "wrong-version", "wrong-bundle", "duplicate-info", "wrong-architecture", "not-executable", "unreceipted", "missing-payload", "symlink", "linked-parent", "hardlink", "writable", "writable-parent", "wrong-cli", "regular-cli", "foreign-service", "foreign-executable", "foreign-service-user", "chroot", "duplicate-service-env", "unknown-service-key", "wrong-receipt-version", "wrong-receipt-volume", "duplicate-path", "foreign-path", "traversal-path", "missing-path", "query-failure", "signature-failure", "oversized"}
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			payload := removalApp + "/Contents/MacOS/netbird"
			path := filepath.Join(f.root, payload)
			rewriteInfo := func(old, new string) {
				f.write(removalApp+"/Contents/Info.plist", []byte(strings.Replace(ownedRemovalInfo, old, new, 1)), 0644)
			}
			rewriteService := func(old, new string) {
				f.write(removalDaemon, []byte(strings.Replace(ownedRemovalService, old, new, 1)), 0644)
			}
			switch kind {
			case "missing-receipt":
				f.must(os.Remove(filepath.Join(f.root, removalReceipt+".bom")))
			case "linked-receipt":
				f.must(os.Link(filepath.Join(f.root, removalReceipt+".plist"), filepath.Join(f.root, "owned-receipt-link")))
			case "empty-info":
				f.write(removalApp+"/Contents/Info.plist", nil, 0644)
			case "wrong-version":
				rewriteInfo("0.78.1", "0.78.2")
			case "wrong-bundle":
				rewriteInfo("io.netbird.client", "io.other.client")
			case "duplicate-info":
				rewriteInfo("</dict>", "<key>CFBundleIdentifier</key><string>io.netbird.client</string></dict>")
			case "wrong-architecture":
				f.write(payload, make([]byte, 32), 0755)
			case "not-executable":
				f.must(os.Chmod(path, 0644))
			case "unreceipted":
				f.write(removalApp+"/Contents/unowned", []byte("owned fixture for unreceipted content"), 0644)
			case "missing-payload":
				f.must(os.Remove(path))
			case "symlink":
				f.must(os.Rename(path, path+"-moved"))
				f.must(os.Symlink(path+"-moved", path))
			case "linked-parent":
				f.must(os.Rename(filepath.Dir(path), filepath.Dir(path)+"-moved"))
				f.must(os.Symlink(filepath.Dir(path)+"-moved", filepath.Dir(path)))
			case "hardlink":
				f.must(os.Link(path, path+"-linked"))
			case "writable":
				f.must(os.Chmod(path, 0777))
			case "writable-parent":
				f.must(os.Chmod(filepath.Dir(path), 0777))
			case "wrong-cli":
				f.must(os.Remove(filepath.Join(f.root, removalCLI)))
				f.must(os.Symlink("/opt/homebrew/bin/netbird", filepath.Join(f.root, removalCLI)))
			case "regular-cli":
				f.must(os.Remove(filepath.Join(f.root, removalCLI)))
				f.write(removalCLI, []byte("owned different installation"), 0755)
			case "foreign-service":
				rewriteService("<string>netbird</string>", "<string>other</string>")
			case "foreign-executable":
				rewriteService("/usr/local/bin/netbird", "/bin/sh")
			case "foreign-service-user":
				rewriteService("<key>KeepAlive</key>", "<key>UserName</key><string>nobody</string><key>KeepAlive</key>")
			case "chroot":
				rewriteService("<key>KeepAlive</key>", "<key>RootDirectory</key><string>/owned</string><key>KeepAlive</key>")
			case "duplicate-service-env":
				rewriteService("<key>OWNED_PRIVATE_VALUE</key>", "<key>OWNED_PRIVATE_VALUE</key><string>duplicate</string><key>OWNED_PRIVATE_VALUE</key>")
			case "unknown-service-key":
				rewriteService("<key>KeepAlive</key>", "<key>Program</key><string>/bin/sh</string><key>KeepAlive</key>")
			case "wrong-receipt-version":
				f.receipt = strings.Replace(f.receipt, "0.78.1", "0.78.2", 1)
			case "wrong-receipt-volume":
				f.receipt = strings.Replace(f.receipt, "<string>/</string>", "<string>/other</string>", 1)
			case "duplicate-path":
				f.paths += removalApp + "\n"
			case "foreign-path":
				f.paths += "Library/unowned\n"
			case "traversal-path":
				f.paths += removalApp + "/../unowned\n"
			case "missing-path":
				f.paths = strings.Replace(f.paths, payload+"\n", "", 1)
			case "query-failure":
				f.readErr = errors.New("owned private query diagnostics")
			case "signature-failure":
				f.signatureErr = errors.New("owned private signature diagnostics")
			case "oversized":
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				f.must(err)
				f.must(file.Truncate(maxRemovalBytes + 1))
				f.must(file.Close())
			}
			if result, err := f.inspect(t.Context()); err != errRemovalFiles || result != nil {
				t.Fatal("invalid native ownership was accepted", kind, err)
			}
		})
	}
}

func TestRemovalFilesDetectMutationDuringPublisherVerification(t *testing.T) {
	for _, kind := range []string{"bytes", "replacement", "permissions", "new-object", "receipt", "service", "link"} {
		t.Run(kind, func(t *testing.T) {
			f := newRemovalFilesFixture(t)
			f.duringSignature = func() {
				name := removalApp + "/Contents/Resources/LICENSE"
				path := filepath.Join(f.root, name)
				switch kind {
				case "bytes":
					f.write(name, []byte("owned changed resource"), 0644)
				case "replacement":
					data, err := os.ReadFile(path)
					f.must(err)
					f.must(os.Remove(path))
					f.write(name, data, 0644)
				case "permissions":
					f.must(os.Chmod(path, 0600))
				case "new-object":
					f.write(removalApp+"/Contents/new", nil, 0644)
				case "receipt":
					f.write(removalReceipt+".bom", []byte("owned different receipt"), 0644)
				case "service":
					f.write(removalDaemon, []byte(strings.Replace(ownedRemovalService, "info", "debug", 1)), 0644)
				case "link":
					f.must(os.Remove(filepath.Join(f.root, removalCLI)))
				}
			}
			if result, err := f.inspect(t.Context()); err != errRemovalFiles || result != nil || f.signatures != 1 {
				t.Fatal("changed ownership survived native verification", err)
			}
		})
	}
}

func TestRemovalFilesFingerprintChangesAndOptionalOwnedServiceObjects(t *testing.T) {
	f := newRemovalFilesFixture(t)
	first, err := f.inspect(t.Context())
	f.must(err)
	path := filepath.Join(f.root, removalApp+"/Contents/Resources/LICENSE")
	data, err := os.ReadFile(path)
	f.must(err)
	f.must(os.Rename(path, path+"-previous"))
	f.write(removalApp+"/Contents/Resources/LICENSE", data, 0644)
	f.must(os.Remove(path + "-previous"))
	replaced, err := f.inspect(t.Context())
	f.must(err)
	if replaced.digest == first.digest {
		t.Fatal("replacement with identical bytes retained native ownership")
	}
	f.must(os.Remove(filepath.Join(f.root, removalDaemon)))
	f.must(os.Remove(filepath.Join(f.root, removalCLI)))
	absentLinks, err := f.inspect(t.Context())
	f.must(err)
	if !absentLinks.objects[removalDaemon].Missing || !absentLinks.objects[removalCLI].Missing || absentLinks.digest == replaced.digest {
		t.Fatal("missing optional objects lost their native state")
	}
	f.write(removalApp+"/Contents/Resources/empty", nil, 0644)
	f.refreshPaths()
	if _, err := f.inspect(t.Context()); err != nil {
		t.Fatal("owned empty resource was rejected", err)
	}
}

func TestRemovalFilesCancellationAndBoundedTree(t *testing.T) {
	f := newRemovalFilesFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := f.inspect(ctx); err != errRemovalFiles || result != nil || f.queries != 0 || f.signatures != 0 {
		t.Fatal("cancelled inspection reached native utilities", err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	f.duringSignature = cancel
	if result, err := f.inspect(ctx); err != errRemovalFiles || result != nil {
		t.Fatal("cancelled verification produced an ownership snapshot", err)
	}
	f = newRemovalFilesFixture(t)
	f.write(removalApp+strings.Repeat("/nested", 18)+"/owned", nil, 0644)
	f.refreshPaths()
	if result, err := f.inspect(t.Context()); err != errRemovalFiles || result != nil || f.signatures != 0 {
		t.Fatal("unbounded native bundle depth accepted", err)
	}
}

func TestRemovalPublisherUsesFixedAppleAndNetbirdRequirements(t *testing.T) {
	root := t.TempDir()
	for _, failAt := range []int{0, 1, 2} {
		calls := 0
		err := verifyRemovalPublisherWith(t.Context(), root, func(ctx context.Context, executable string, args []string, limit int64, consume func(io.Reader) error) error {
			calls++
			if executable != "/usr/bin/codesign" || len(args) != 7 || !slices.Equal(args[:5], []string{"--verify", "--deep", "--strict", "--all-architectures", "-R"}) || !strings.Contains(args[5], `certificate leaf[subject.OU] = "TA739QLA7A"`) || !strings.Contains(args[5], "anchor apple generic") || !strings.HasPrefix(args[6], root+"/") || limit != 16<<10 {
				t.Fatal("native publisher verification weakened")
			}
			if calls == failAt {
				return errors.New("owned verification failure")
			}
			return consume(strings.NewReader("owned discarded diagnostics"))
		})
		if (err == nil) != (failAt == 0) || failAt == 0 && calls != 2 || failAt > 0 && calls != failAt {
			t.Fatal("publisher failure was ignored", err)
		}
	}
}

func FuzzRemovalNativePlist(f *testing.F) {
	f.Add(ownedRemovalInfo)
	f.Add(ownedRemovalService)
	f.Add(ownedReceipt)
	f.Fuzz(func(t *testing.T, data string) {
		if removalBundleIdentity([]byte(data), "0.78.1") && removalBundleIdentity([]byte(data), "0.78.2") {
			t.Fatal("ambiguous native bundle version")
		}
		_ = removalServiceIdentity([]byte(data), true)
		_ = removalServiceIdentity([]byte(data), false)
	})
}
