//go:build darwin

package netbirdinstall

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// The native utility only receives a disposable volume and a unique owned ID.
// No vendor package, host receipt, installer or daemon is read or changed.
func TestNativeRemovalReceiptListUsesOwnedVolumeAndHandlesEmptyDatabase(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "private/var/db/receipts")
	if err := os.MkdirAll(database, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("private/var", filepath.Join(root, "var")); err != nil {
		t.Fatal(err)
	}
	packageID := "io.openuem.owned-removal-receipt." + uuid.NewString()
	payload := filepath.Join(root, "payload")
	if err := os.Mkdir(payload, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, "inert.txt"), []byte("owned inert receipt fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	plist, bom := filepath.Join(database, packageID+".plist"), filepath.Join(database, packageID+".bom")
	for _, phase := range []string{"present", "plist-only", "bom-only", "absent"} {
		t.Run(phase, func(t *testing.T) {
			if phase == "present" || phase == "plist-only" {
				data := fmt.Sprintf(`<plist version="1.0"><dict><key>PackageIdentifier</key><string>%s</string><key>PackageVersion</key><string>1.2.3</string><key>InstallPrefixPath</key><string></string><key>InstallDate</key><date>2026-09-14T10:00:00Z</date></dict></plist>`, packageID)
				if err := os.WriteFile(plist, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(plist); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if phase == "present" || phase == "bom-only" {
				if err := exec.CommandContext(t.Context(), "/usr/bin/mkbom", payload, bom).Run(); err != nil {
					t.Fatal("owned BOM creation failed", err)
				}
			} else if err := os.Remove(bom); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			var present bool
			err := readNativePackage(t.Context(), "/usr/sbin/pkgutil", []string{"--volume", root, "--pkgs-plist"}, maxRemovalReceiptList, func(reader io.Reader) error {
				var err error
				present, err = removalReceiptListed(reader, packageID)
				return err
			})
			if err != nil || present != (phase == "present" || phase == "bom-only") {
				t.Fatal("native receipt list did not preserve explicit complete/partial/absent state", err)
			}
			if phase != "absent" {
				// Native recovery uses pkgutil for recognized records. An orphan
				// plist is not recognized and cannot be forgotten by that command.
				before, beforeErr := os.ReadFile(plist)
				err := runNativeInstaller(t.Context(), "/usr/sbin/pkgutil", []string{"--volume", root, "--forget", packageID})
				if phase == "plist-only" {
					after, afterErr := os.ReadFile(plist)
					if err == nil || beforeErr != nil || afterErr != nil || string(after) != string(before) {
						t.Fatal("native orphan receipt unexpectedly became a recognized forget operation")
					}
				} else {
					if err != nil {
						t.Fatal("owned native receipt forget failed", err)
					}
					for _, name := range []string{plist, bom} {
						if _, err := os.Lstat(name); !os.IsNotExist(err) {
							t.Fatal("native receipt forget retained an owned receipt", err)
						}
					}
				}
				if data, err := os.ReadFile(filepath.Join(payload, "inert.txt")); err != nil || string(data) != "owned inert receipt fixture" {
					t.Fatal("native receipt forget mutated installed payload", err)
				}
				return
			}
			// Reproduce the old empty-search failure using only the owned ID.
			err = readNativePackage(t.Context(), "/usr/sbin/pkgutil", []string{"--volume", root, "--pkgs=^" + strings.ReplaceAll(packageID, ".", "[.]") + "$"}, 4096, func(reader io.Reader) error { _, err := io.ReadAll(reader); return err })
			if err == nil {
				t.Fatal("expected native no-match exit status was not observed")
			}
			// Exercise the production absence verifier with the real native typed
			// output, redirecting its fixed root volume to this disposable fixture.
			err = verifyNativeRemovalAbsence(t.Context(), root, uint32(os.Geteuid()), func(ctx context.Context, path string, args []string, limit int64, consume func(io.Reader) error) error {
				if path != "/usr/sbin/pkgutil" || !reflect.DeepEqual(args, []string{"--volume", "/", "--pkgs-plist"}) {
					t.Fatal("unexpected native fixture query")
				}
				return readNativePackage(ctx, path, []string{"--volume", root, "--pkgs-plist"}, limit, consume)
			}, func(context.Context, string) error { return nil })
			if err != nil {
				t.Fatal("successful native empty receipt database did not establish absence", err)
			}
		})
	}
}
