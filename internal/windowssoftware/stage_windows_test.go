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
	"time"

	"github.com/open-uem/openuem-agent/internal/packagesignature"
	"golang.org/x/sys/windows"
)

func holdOwnedStageReadHandle(t *testing.T, path string) func() {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		t.Fatal(err)
	}
	close := func() {
		if handle != 0 {
			if err := windows.CloseHandle(handle); err != nil {
				t.Error("owned sharing handle did not close", err)
			}
			handle = 0
		}
	}
	t.Cleanup(close)
	return close
}

func TestNativeWindowsSoftwareStagingJoinsTransientCleanup(t *testing.T) {
	for _, target := range []string{"file", "directory"} {
		t.Run(target, func(t *testing.T) {
			f := newStageFixture(t)
			stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, func(context.Context, string, string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			path := stage.Path()
			if target == "directory" {
				path = stage.directory
			}
			release := holdOwnedStageReadHandle(t, path)
			attempts := 0
			err = stage.close(func(current string) error {
				err := os.Remove(current)
				if current == path {
					attempts++
					if attempts == 1 {
						if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
							t.Error("owned read handle did not reproduce native deletion contention", err)
						}
						release()
					}
				}
				return err
			})
			if err != nil || attempts != 2 || stage.Close() != nil || stage.Path() != "" || stage.Verify(t.Context()) == nil {
				t.Fatal("transient native contention left an executable candidate", attempts, err)
			}
			assertStageEmpty(t, f.root)
		})
	}
}

func TestNativeWindowsSoftwareStagingBoundsPermanentCleanupFailure(t *testing.T) {
	f := newStageFixture(t)
	stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	path := stage.Path()
	holdOwnedStageReadHandle(t, path)
	started := time.Now()
	err = stage.Close()
	elapsed := time.Since(started)
	if err != ErrArtifactChanged || elapsed < 1500*time.Millisecond || elapsed > 4*time.Second {
		t.Fatal("permanent native contention lost its bounded failure", elapsed, err)
	}
	if stage.Close() != err || stage.Path() != "" || stage.Verify(t.Context()) == nil {
		t.Fatal("repeated close hid failed cleanup or reopened the candidate")
	}
	entry, statErr := os.Lstat(path)
	if statErr != nil || !os.SameFile(entry, stage.fileInfo) {
		t.Fatal("failed cleanup changed the retained private candidate", statErr)
	}
}

func TestNativeWindowsSoftwareStagingRechecksIdentityDuringCleanup(t *testing.T) {
	f := newStageFixture(t)
	stage, err := stageArtifact(t.Context(), f.artifact, f.root, f.client, func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// Drop only our original protection to simulate an administrator replacing
	// the candidate after the first failed deletion, before the next attempt.
	if err = stage.file.Close(); err != nil {
		t.Fatal(err)
	}
	stage.file = nil
	path := stage.Path()
	release := holdOwnedStageReadHandle(t, path)
	attempts := 0
	foreign := []byte("owned replacement must survive")
	err = removeStagedEntry(path, stage.fileInfo, time.Now().Add(time.Second), func(current string) error {
		attempts++
		err := os.Remove(current)
		if attempts == 1 {
			if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
				t.Fatal("owned contention was not established", err)
			}
			release()
			if renameErr := os.Rename(path, path+".original"); renameErr != nil {
				t.Fatal(renameErr)
			}
			if writeErr := os.WriteFile(path, foreign, 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
		}
		return err
	})
	data, readErr := os.ReadFile(path)
	if err != ErrArtifactChanged || attempts != 1 || readErr != nil || string(data) != string(foreign) {
		t.Fatal("retry removed a replacement without the original file identity", attempts, err, readErr)
	}
	if original, statErr := os.Lstat(path + ".original"); statErr != nil || !os.SameFile(original, stage.fileInfo) {
		t.Fatal("cleanup touched the displaced original candidate", statErr)
	}
}

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
