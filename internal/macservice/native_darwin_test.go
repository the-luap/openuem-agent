//go:build darwin && cgo

package macservice

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/open-uem/openuem-agent/internal/macbundle"
)

func signedFixture(t *testing.T) string {
	t.Helper()
	parent, err := os.MkdirTemp("/private/tmp", "uem-app-service-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Error(err)
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// A root CI test may run a runner-owned compiled test binary. Make an owned
	// fixture copy before applying the production builder's source-owner rules.
	input, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	source := filepath.Join(parent, "fixture-source")
	output, err := os.OpenFile(source, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("could not create the owned source fixture", copyErr, closeErr)
	}
	result, err := macbundle.Build(context.Background(), macbundle.Options{Agent: source, Output: parent, Version: "0.12.0", Build: 42, Architecture: runtime.GOARCH})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--force", "--sign", "-", result.Path).CombinedOutput(); err != nil {
		t.Fatal("isolated ad-hoc signing failed", err, string(output))
	}
	return result.Path
}

func TestNativeSealedBundleRejectsDeveloperIDSubstitutionAndChangedMetadata(t *testing.T) {
	bundle := signedFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	files, err := inspectBundle(bundle, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal("builder layout was rejected", err)
	}
	defer files.Close()
	if err := verifyApp(ctx, bundle, ""); err != nil {
		t.Fatal("ad-hoc resource seal failed", err)
	}
	if err := verifyApp(ctx, bundle, releaseRequirement); !errors.Is(err, ErrSignature) {
		t.Fatal("ad-hoc signature was treated as notarized Developer ID", err)
	}
	if _, err := Open(ctx, filepath.Join(bundle, macbundle.ExecutableRelative)); !errors.Is(err, ErrAccess) {
		t.Fatal("temporary bundle reached production registration admission", err)
	}
	plist := filepath.Join(bundle, macbundle.DaemonRelative)
	data, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	if err := files.Check(); !errors.Is(err, ErrAccess) {
		t.Fatal("retained metadata change accepted", err)
	}
	if err := verifyApp(ctx, bundle, ""); !errors.Is(err, ErrSignature) {
		t.Fatal("modified resource seal accepted", err)
	}
}

func TestNativeReleaseRequirementIsAcceptedByTheSystemCompiler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output := filepath.Join(t.TempDir(), "release-requirement.csreq")
	if diagnostic, err := exec.CommandContext(ctx, "/usr/bin/csreq", "-r", releaseRequirement, "-b", output).CombinedOutput(); err != nil {
		t.Fatal("release policy is not a native code requirement", err, string(diagnostic))
	}
	if info, err := os.Stat(output); err != nil || info.Size() == 0 {
		t.Fatal("native requirement compiler produced no policy", err)
	}
}

func TestNativeCodeDescriptorsRejectReplacementAndWritableMetadata(t *testing.T) {
	bundle := signedFixture(t)
	files, err := inspectBundle(bundle, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	path := filepath.Join(bundle, "Contents/Info.plist")
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".old", path); err != nil {
		t.Fatal(err)
	}
	if err := files.Check(); !errors.Is(err, ErrAccess) {
		t.Fatal("metadata alias accepted", err)
	}
	if _, err := inspectBundle(bundle, uint32(os.Geteuid())); !errors.Is(err, ErrAccess) {
		t.Fatal("new admission followed metadata alias", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".old", path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectBundle(bundle, uint32(os.Geteuid())); !errors.Is(err, ErrAccess) {
		t.Fatal("writable metadata accepted", err)
	}
}

var bundleContextFixture = flag.String("openuem-app-context-fixture", "", "Isolated read-only bundle context fixture")

func TestNativeBundleContextHelper(t *testing.T) {
	if *bundleContextFixture == "" {
		t.Skip("isolated subprocess only")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	service, err := currentBundleService(*bundleContextFixture, executable)
	if err != nil {
		t.Fatal("Foundation did not recognize the current GUI-less app bundle", err)
	}
	defer service.close()
	if _, err := service.status(); err != nil {
		t.Fatal("native read-only authorization query failed", err)
	}
	if other, err := currentBundleService(*bundleContextFixture+".foreign", executable); !errors.Is(err, ErrAccess) || other != nil {
		t.Fatal("another app was accepted as the caller")
	}
	// Deliberately do not call register: Developer ID/notarization and a final
	// installed enrollment are required before any production OS mutation.
}

func TestNativeFoundationRecognizesActualCopiedExecutableBundle(t *testing.T) {
	bundle := signedFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(bundle, macbundle.ExecutableRelative), "-test.run=^TestNativeBundleContextHelper$", "-openuem-app-context-fixture="+bundle)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatal("bundled context subprocess failed", err, string(output))
	}
}
