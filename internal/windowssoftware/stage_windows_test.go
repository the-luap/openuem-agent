//go:build windows

package windowssoftware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-uem/openuem-agent/internal/packagesignature"
)

func TestNativeWindowsSoftwareStagingExcludesWriteDeleteAndReplacement(t *testing.T) {
	f := newStageFixture(t)
	stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	path := stage.Path()
	if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		file.Close()
		t.Fatal("protected installer allowed concurrent write")
	}
	if err := os.Remove(path); err == nil {
		t.Fatal("protected installer allowed delete")
	}
	if err := os.Rename(path, path+".replaced"); err == nil {
		t.Fatal("protected installer allowed rename")
	}
	if err := stage.Verify(t.Context()); err != nil {
		t.Fatal("failed interference changed file", err)
	}
}

func TestNativeWindowsSoftwareStagingVerifiesActualAuthenticodeWithoutExecution(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "signed", true: "changed_signature"}[corrupt], func(t *testing.T) {
			f := newStageFixture(t)
			// This existing Go-project EV-signed fixture is copied and verified only.
			// Its license and provenance live beside it; no candidate is executed.
			content, err := os.ReadFile(filepath.Join("..", "packagesignature", "testdata", "ev-signed-file.exe"))
			if err != nil {
				t.Fatal(err)
			}
			if corrupt {
				content[0] ^= 1
			}
			f.content = content
			hash := sha256.Sum256(content)
			f.artifact.SHA256 = hex.EncodeToString(hash[:])
			stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, packagesignature.Verify)
			if corrupt {
				if stage != nil || !errors.Is(err, ErrArtifactSignature) {
					t.Fatal("matching hash bypassed damaged Authenticode", err)
				}
			} else {
				if err != nil || stage == nil {
					t.Fatal("signed candidate did not cross download/hash/native policy", err)
				}
				if stage.Close() != nil {
					t.Fatal("signed fixture cleanup failed")
				}
			}
			assertStageEmpty(t, f.root)
		})
	}
}
