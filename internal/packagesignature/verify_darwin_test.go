package packagesignature

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestMacAssessmentRequiresExplicitNotarizedDeveloperIDSource(t *testing.T) {
	for _, tc := range []struct {
		output   string
		accepted bool
	}{
		{"fixture.pkg: accepted\nsource=Notarized Developer ID\n", true},
		{"fixture.pkg: accepted\r\nsource=Notarized Developer ID\r\n", true},
		{"fixture.pkg: accepted\nsource=Developer ID\n", false},
		{"fixture.pkg: accepted\nsource=Apple System\n", false},
		{"fixture.pkg: accepted\nsource=Local rule\n", false},
		{"fixture.pkg: accepted\nsource=Unnotarized Developer ID\n", false},
		{"fixture.pkg: accepted\n", false},
		{"source=Notarized Developer ID\nsource=Notarized Developer ID\n", false},
		{"source=Notarized Developer ID\nsource=Local rule\n", false},
		{"source=Notarized Developer ID override\n", false},
	} {
		if notarizedAssessment([]byte(tc.output)) != tc.accepted {
			t.Fatal("incorrect native notarization source decision")
		}
	}
}

func TestMacRejectsActualUnsignedInstallerWithoutInstallingItsPayload(t *testing.T) {
	directory := privateTestDirectory(t)
	root := filepath.Join(directory, "payload")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "fixture.txt"), []byte("non-executable isolated test payload"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "unsigned.pkg")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/pkgbuild", "--root", root, "--identifier", "org.openuem.tests.signature", "--version", "1", path)
	if err := command.Run(); err != nil {
		t.Fatal("could not create isolated unsigned installer", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, path, "pkg"); !errors.Is(err, ErrUntrusted) {
		t.Fatal("unsigned installer passed native policy", err)
	}
}
