package macbundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

func nativeFixture(t *testing.T) Options {
	t.Helper()
	o := fixtureOptions(t)
	if err := os.WriteFile(o.Agent, fixtureImage(macho.CpuArm64), 0755); err != nil {
		t.Fatal(err)
	}
	return o
}

func noStaging(t *testing.T, o Options, published bool) {
	t.Helper()
	entries, err := os.ReadDir(o.Output)
	if err != nil {
		t.Fatal(err)
	}
	if published {
		if len(entries) != 1 || entries[0].Name() != BundleName {
			t.Fatal("build retained temporary data or changed a competing output")
		}
	} else if len(entries) != 0 {
		t.Fatal("failed build left a completed or temporary bundle")
	}
}

func TestNativeBundlePublishesOnceAndPreservesSource(t *testing.T) {
	o := nativeFixture(t)
	before, _ := os.ReadFile(o.Agent)
	result, err := Build(context.Background(), o)
	if err != nil || !result.Published || !result.RequiresReleaseSigning || result.Path != filepath.Join(o.Output, BundleName) {
		t.Fatal("bundle assembly failed", result, err)
	}
	actual, err := os.ReadFile(filepath.Join(result.Path, ExecutableRelative))
	if err != nil || !bytes.Equal(actual, before) {
		t.Fatal("bundle executable differs from its input", err)
	}
	for path, mode := range map[string]os.FileMode{".": 0755, "Contents": 0755, "Contents/MacOS": 0755, "Contents/Library": 0755, "Contents/Library/LaunchDaemons": 0755, ExecutableRelative: 0755, "Contents/Info.plist": 0644, DaemonRelative: 0644} {
		info, err := os.Lstat(filepath.Join(result.Path, path))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("unexpected installed code mode", path, err)
		}
	}
	if _, err := Build(context.Background(), o); !errors.Is(err, ErrExists) {
		t.Fatal("existing bundle was replaced", err)
	}
	after, _ := os.ReadFile(o.Agent)
	if !bytes.Equal(before, after) {
		t.Fatal("assembly changed its source")
	}
	noStaging(t, o, true)
}

func TestNativeBundleRejectsUnsafeInputsAndInterruptedPublication(t *testing.T) {
	for _, scenario := range []string{"source-alias", "output-alias", "public-output", "writable-source", "wrong-architecture", "canceled", "changed-source", "replaced-source", "replaced-parent", "competing-symlink"} {
		t.Run(scenario, func(t *testing.T) {
			o := nativeFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var hook func()
			want := ErrSource
			switch scenario {
			case "source-alias":
				if err := os.Symlink(o.Agent, o.Agent+".alias"); err != nil {
					t.Fatal(err)
				}
				o.Agent += ".alias"
			case "output-alias":
				alias := filepath.Join(t.TempDir(), "output")
				if err := os.Symlink(o.Output, alias); err != nil {
					t.Fatal(err)
				}
				o.Output, want = alias, ErrOutput
			case "public-output":
				if err := os.Chmod(o.Output, 0755); err != nil {
					t.Fatal(err)
				}
				want = ErrOutput
			case "writable-source":
				if err := os.Chmod(o.Agent, 0777); err != nil {
					t.Fatal(err)
				}
			case "wrong-architecture":
				o.Architecture = "amd64"
			case "canceled":
				want, hook = context.Canceled, cancel
			case "changed-source":
				info, _ := os.Stat(o.Agent)
				hook = func() {
					data := fixtureImage(macho.CpuArm64)
					data[len(data)-1] = 1
					if err := os.WriteFile(o.Agent, data, 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(o.Agent, info.ModTime(), info.ModTime()); err != nil {
						t.Fatal(err)
					}
				}
			case "replaced-source":
				hook = func() {
					if err := os.Rename(o.Agent, o.Agent+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(o.Agent, fixtureImage(macho.CpuArm64), 0755); err != nil {
						t.Fatal(err)
					}
				}
			case "replaced-parent":
				want = ErrOutput
				hook = func() {
					if err := os.Rename(o.Output, o.Output+".old"); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { os.Remove(o.Output + ".old") })
					if err := os.Mkdir(o.Output, 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "competing-symlink":
				want = ErrExists
				hook = func() {
					if err := os.Symlink(o.Agent, filepath.Join(o.Output, BundleName)); err != nil {
						t.Fatal(err)
					}
				}
			}
			result, err := build(ctx, o, hook)
			if !errors.Is(err, want) || result.Published {
				t.Fatal("unsafe or interrupted build published output", result, err)
			}
			noStaging(t, o, scenario == "competing-symlink")
			if scenario == "replaced-parent" {
				old := o
				old.Output += ".old"
				noStaging(t, old, false)
			}
		})
	}
}

func TestNativeConcurrentBundleAssemblyCannotReplaceTheWinner(t *testing.T) {
	o := nativeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var workers sync.WaitGroup
	ready := make(chan struct{}, 2)
	gate := make(chan struct{})
	openGate := sync.OnceFunc(func() { close(gate) })
	results := make(chan error, 2)
	defer func() { cancel(); openGate(); workers.Wait() }()
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, err := build(ctx, o, func() {
				ready <- struct{}{}
				select {
				case <-gate:
				case <-ctx.Done():
				}
			})
			results <- err
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-ready:
		case err := <-results:
			t.Fatal("assembly failed before the publication gate", err)
		case <-ctx.Done():
			t.Fatal("assembly did not reach the publication gate")
		}
	}
	openGate()
	a, b := <-results, <-results
	if !((a == nil && errors.Is(b, ErrExists)) || (b == nil && errors.Is(a, ErrExists))) {
		t.Fatal("concurrent publication did not preserve one winner", a, b)
	}
	noStaging(t, o, true)
}

func nativeCommand(t *testing.T, path string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("native fixture command timed out")
	}
	return output, err
}

func TestActualMacExecutableBundleMetadataAndCodeSignatureSeal(t *testing.T) {
	o := fixtureOptions(t)
	var err error
	o.Agent, err = os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	o.Architecture = runtime.GOARCH
	before, err := os.ReadFile(o.Agent)
	if err != nil {
		t.Fatal(err)
	}
	original := sha256.Sum256(before)
	result, err := Build(context.Background(), o)
	if err != nil {
		t.Fatal("actual native executable could not be bundled", err)
	}
	decodePlist := func(path string) map[string]any {
		output, err := nativeCommand(t, "/usr/bin/plutil", "-convert", "json", "-o", "-", "--", filepath.Join(result.Path, path))
		if err != nil {
			t.Fatal("native plist decoder rejected bundle metadata", err, string(output))
		}
		var value map[string]any
		if err := json.Unmarshal(output, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	info, daemon := decodePlist("Contents/Info.plist"), decodePlist(DaemonRelative)
	if info["CFBundleIdentifier"] != BundleIdentifier || info["CFBundleVersion"] != "42" || info["CFBundleShortVersionString"] != o.Version || info["CFBundleExecutable"] != "openuem-agent" || info["LSMinimumSystemVersion"] != MinimumSystemVersion {
		t.Fatal("native app metadata differs from release options")
	}
	if daemon["Label"] != DaemonLabel || daemon["BundleProgram"] != ExecutableRelative || daemon["UserName"] != "root" || daemon["Umask"] != float64(63) || !reflect.DeepEqual(daemon["ProgramArguments"], []any{"openuem-agent", "serve", "-identity-directory", IdentityDirectory}) {
		t.Fatal("native service metadata changed its executable, privilege or identity selection")
	}
	if _, exists := daemon["Program"]; exists {
		t.Fatal("bundle daemon used a mutable absolute executable path")
	}
	// Ad-hoc signing exercises only the local resource seal. It is not Developer
	// ID/notarization acceptance and never registers or runs the fixture bundle.
	if output, err := nativeCommand(t, "/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", result.Path); err != nil {
		t.Fatal("fixture bundle signing failed", err, string(output))
	}
	if output, err := nativeCommand(t, "/usr/bin/codesign", "--verify", "--strict", result.Path); err != nil {
		t.Fatal("native resource seal is invalid", err, string(output))
	}
	file := filepath.Join(result.Path, DaemonRelative)
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(data, []byte("\n<!-- changed fixture metadata -->\n")...), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeCommand(t, "/usr/bin/codesign", "--verify", "--strict", result.Path); err == nil {
		t.Fatal("modified daemon metadata passed the app resource seal")
	}
	after, err := os.ReadFile(o.Agent)
	if err != nil || sha256.Sum256(after) != original {
		t.Fatal("bundle signing modified the original running executable", err)
	}
}
