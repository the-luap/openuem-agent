package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const ownedInstallInfo = `<pkg-info identifier="io.netbird.client" version="0.78.1" relocatable="false" postinstall-action="none"/>`

func ownedInstallPackage(t *testing.T, info string) (*Prepared, packageapi.Package) {
	t.Helper()
	data := ownedXARInfo(nil, info)
	descriptor, client, root := packageFixture(t, "pkg", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) })
	hash := sha256.Sum256(data)
	descriptor.Size, descriptor.SHA256, descriptor.Version, descriptor.Architecture = int64(len(data)), hex.EncodeToString(hash[:]), "0.78.1", "arm64"
	p, err := stage(t.Context(), descriptor, root, client, noNative)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p, descriptor
}

func inertInstallationBackend() installationBackend {
	return installationBackend{
		source:    func(context.Context, string) error { return nil },
		signature: noNative,
		preflight: func(context.Context, map[string]installedFile) error { return nil },
		run:       func(context.Context, string, []string) error { return nil },
		result:    func(context.Context, packageapi.Package, map[string]installedFile) error { return nil },
	}
}

func TestNativeInstallationPlanBindsExactBytesArgumentsAndResult(t *testing.T) {
	p, descriptor := ownedInstallPackage(t, ownedInstallInfo)
	backend := inertInstallationBackend()
	signatures, starts, results := 0, 0, 0
	path := p.Path()
	backend.signature = func(_ context.Context, got, format string) error {
		signatures++
		if got != path || format != "pkg" {
			t.Error("signature source changed")
		}
		return nil
	}
	backend.run = func(_ context.Context, executable string, args []string) error {
		starts++
		if executable != "/usr/sbin/installer" || !reflect.DeepEqual(args, []string{"-pkg", path, "-target", "/"}) {
			t.Error("installer did not use literal fixed arguments")
		}
		return nil
	}
	backend.result = func(_ context.Context, got packageapi.Package, files map[string]installedFile) error {
		results++
		if got != descriptor || len(files) != 2 {
			t.Error("result lost approved package identity")
		}
		for _, name := range []string{"netbird", "netbird-ui"} {
			file := files["Applications/NetBird.app/Contents/MacOS/"+name]
			if file.hash != sha256.Sum256(ownedCode("arm64")) || file.size != 32 || !file.executable {
				t.Error("result was not bound to complete payload bytes")
			}
		}
		return nil
	}
	plan, err := p.prepareInstallation(t.Context(), descriptor, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { plan.Close() })
	if signatures != 1 || starts != 0 || results != 0 {
		t.Fatal("preflight executed the installer")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", plan, plan), descriptor.URL) {
		t.Fatal("plan exposed source")
	}
	if err = plan.Run(t.Context()); err != nil || starts != 1 || results != 1 {
		t.Fatal("native result was not verified", err)
	}
	if err = plan.Run(t.Context()); err == nil || starts != 1 {
		t.Fatal("native plan repeated execution")
	}
	if err = plan.Close(); err != nil {
		t.Fatal(err)
	}
	if err = p.Verify(t.Context(), descriptor); err != nil {
		t.Fatal("plan did not release original artifact", err)
	}
}

func TestNativeInstallationRejectsSignatureTargetAndResultChanges(t *testing.T) {
	for _, kind := range []string{"signature", "preflight", "source", "relocation", "restart", "execution", "result"} {
		t.Run(kind, func(t *testing.T) {
			info := ownedInstallInfo
			if kind == "relocation" {
				info = strings.Replace(info, `relocatable="false"`, `relocatable="true"`, 1)
			}
			if kind == "restart" {
				info = strings.Replace(info, `postinstall-action="none"`, `postinstall-action="restart"`, 1)
			}
			p, descriptor := ownedInstallPackage(t, info)
			backend := inertInstallationBackend()
			calls := 0
			backend.run = func(context.Context, string, []string) error {
				calls++
				if kind == "execution" {
					return errors.New("owned execution failure")
				}
				return nil
			}
			if kind == "signature" {
				backend.signature = func(context.Context, string, string) error { return errors.New("owned invalid signature") }
			}
			if kind == "preflight" {
				backend.preflight = func(context.Context, map[string]installedFile) error { return errors.New("owned unsafe target") }
			}
			if kind == "result" {
				backend.result = func(context.Context, packageapi.Package, map[string]installedFile) error {
					return errors.New("owned mismatched installed state")
				}
			}
			if kind == "source" {
				descriptor.URL += "-changed"
			}
			plan, err := p.prepareInstallation(t.Context(), descriptor, backend)
			if kind != "execution" && kind != "result" {
				if err == nil {
					plan.Close()
					t.Fatal("invalid native preflight succeeded")
				}
				if calls != 0 {
					t.Fatal("invalid preflight reached native process")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { plan.Close() })
			if err = plan.Run(t.Context()); err == nil || calls != 1 {
				t.Fatal("native failure became success")
			}
		})
	}
}

func TestNativeInstallationCloseJoinsProcessBeforePreparedCleanup(t *testing.T) {
	p, descriptor := ownedInstallPackage(t, ownedInstallInfo)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	backend := inertInstallationBackend()
	var checks atomic.Int32
	backend.run = func(ctx context.Context, _ string, _ []string) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return ctx.Err()
	}
	backend.result = func(context.Context, packageapi.Package, map[string]installedFile) error { checks.Add(1); return nil }
	plan, err := p.prepareInstallation(ctx, descriptor, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { plan.Close() })
	run := make(chan error, 1)
	go func() { run <- plan.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native process not entered")
	}
	closed, cleaned := make(chan error, 1), make(chan error, 1)
	go func() { closed <- plan.Close() }()
	go func() { cleaned <- p.Close() }()
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("cancellation missing")
	}
	select {
	case <-closed:
		t.Fatal("plan closed before process joined")
	default:
	}
	select {
	case <-cleaned:
		t.Fatal("prepared package removed during process")
	default:
	}
	close(release)
	if err = <-run; err == nil {
		t.Fatal("cancelled process succeeded")
	}
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
	if err = <-cleaned; err != nil || checks.Load() != 0 {
		t.Fatal("cleanup or cancellation result invalid", err)
	}
}

const ownedReceipt = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>pkgid</key><string>io.netbird.client</string><key>pkg-version</key><string>0.78.1</string><key>volume</key><string>/</string><key>install-location</key><string>/</string><key>install-time</key><integer>1789360000</integer><key>receipt-plist-version</key><real>1</real></dict></plist>`

func TestNativeReceiptExactIdentityAndUnambiguousPlist(t *testing.T) {
	descriptor := metadataDescriptor("pkg")
	if err := verifyNativeReceipt(strings.NewReader(ownedReceipt), descriptor); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(string) string{
		func(s string) string { return strings.Replace(s, "io.netbird.client", "foreign.pkg", 1) },
		func(s string) string { return strings.Replace(s, "0.78.1", "0.78.2", 1) },
		func(s string) string { return strings.Replace(s, "<string>/</string>", "<string>/other</string>", 1) },
		func(s string) string {
			return strings.Replace(s, "</dict>", "<key>pkgid</key><string>io.netbird.client</string></dict>", 1)
		},
		func(s string) string { return strings.Replace(s, "<key>install-time</key>", "<key>absent</key>", 1) },
		func(s string) string {
			return strings.Replace(s, "<integer>1789360000</integer>", "<string>1789360000</string>", 1)
		},
		func(s string) string {
			return strings.Replace(s, "<integer>1789360000</integer>", "<integer>0</integer>", 1)
		},
		func(s string) string { return s + s },
		func(s string) string { return s + "<!DOCTYPE plist>" },
		func(s string) string { return s + strings.Repeat(" ", 32<<10) },
	} {
		if err := verifyNativeReceipt(strings.NewReader(change(ownedReceipt)), descriptor); err == nil {
			t.Fatal("ambiguous or mismatched receipt accepted")
		}
	}
}

func FuzzNativeInstallationReceipt(f *testing.F) {
	f.Add(ownedReceipt)
	f.Add(`<plist version="1.0"><dict/></plist>`)
	f.Fuzz(func(t *testing.T, data string) {
		p := metadataDescriptor("pkg")
		if verifyNativeReceipt(strings.NewReader(data), p) != nil {
			return
		}
		p.Version += "-different"
		if verifyNativeReceipt(strings.NewReader(data), p) == nil {
			t.Fatal("receipt matches conflicting native versions")
		}
	})
}
