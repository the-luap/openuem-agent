//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
	"github.com/stretchr/testify/require"
)

func TestNativeInspectionHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--netbird-inspection-fixture" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "output":
		fmt.Print("owned\n")
	case "environment":
		for _, key := range []string{"NB_SETUP_KEY", "HTTP_PROXY", "HTTPS_PROXY", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "DPKG_DEB_THREADS_MAX", "RPM_CONFIGDIR"} {
			if os.Getenv(key) != "" {
				os.Exit(2)
			}
		}
		if os.Getenv("HOME") != "/nonexistent" || os.Getenv("LC_ALL") != "C" || syscall.Getpgrp() != os.Getpid() {
			os.Exit(3)
		}
		fmt.Print("clean\n")
	case "stdout-overflow":
		fmt.Print(strings.Repeat("x", 8192))
	case "stderr-overflow":
		fmt.Fprint(os.Stderr, strings.Repeat("private", 2048))
	case "nonzero":
		fmt.Print("owned\n")
		fmt.Fprint(os.Stderr, "private diagnostic")
		os.Exit(1)
	case "wait":
		fmt.Println(os.Getpid())
		time.Sleep(time.Minute)
	default:
		os.Exit(4)
	}
	os.Exit(0)
}

func TestNativeInspectionProcessLifecycle(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	for _, key := range []string{"NB_SETUP_KEY", "HTTP_PROXY", "HTTPS_PROXY", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "DPKG_DEB_THREADS_MAX", "RPM_CONFIGDIR"} {
		t.Setenv(key, "owned-private-value")
	}
	for _, mode := range []string{"output", "environment", "stdout-overflow", "stderr-overflow", "nonzero", "parser-failure", "parser-short-read", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			helper := mode
			if mode == "cancel" || mode == "deadline" {
				helper = "wait"
			}
			if mode == "parser-failure" || mode == "parser-short-read" {
				helper = "stdout-overflow"
			}
			if mode == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 300*time.Millisecond)
				defer stop()
			}
			pid := 0
			data := ""
			err := readNativePackage(ctx, executable, []string{"-test.run=^TestNativeInspectionHelper$", "--", "--netbird-inspection-fixture", helper}, 4096, func(reader io.Reader) error {
				if mode == "parser-failure" {
					return ErrMetadata
				}
				if mode == "parser-short-read" {
					return nil
				}
				if mode == "cancel" || mode == "deadline" {
					var byteData [1]byte
					var line strings.Builder
					for line.Len() < 20 {
						if _, err := io.ReadFull(reader, byteData[:]); err != nil {
							return err
						}
						if byteData[0] == '\n' {
							break
						}
						line.WriteByte(byteData[0])
					}
					pid, err = strconv.Atoi(line.String())
					if err != nil {
						return err
					}
					if mode == "cancel" {
						cancel()
					}
				}
				bytes, err := io.ReadAll(reader)
				data = string(bytes)
				return err
			})
			if mode == "output" || mode == "environment" {
				require.NoError(t, err)
				require.NotEmpty(t, data)
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "private")
			}
			if mode == "cancel" || mode == "deadline" {
				require.Positive(t, pid)
				require.ErrorIs(t, syscall.Kill(pid, 0), syscall.ESRCH, "child must be reaped before return")
			}
		})
	}
}

// This opt-in check reads exact public release artifacts through system package
// tools. It neither installs a package nor invokes a NetBird executable.
func TestOfficialNativePackageMetadata(t *testing.T) {
	root := os.Getenv("NETBIRD_PACKAGE_EVIDENCE")
	if root == "" {
		t.Skip("set NETBIRD_PACKAGE_EVIDENCE to the verified v0.78.1 artifact directory")
	}
	for _, item := range []struct{ format, name, hash string }{
		{"pkg", "netbird_0.78.1_darwin_arm64.pkg", "220f9187aa92c22f20107b9291fd41ab0742e6a70ba8cd360286d6ddf35db585"},
		{"deb", "netbird_0.78.1_linux_arm64.deb", "ae3a9e2c3207c78431a2003a6677a4ad5f71a86b139ff17fa32484fbc5022f3c"},
		{"rpm", "netbird_0.78.1_linux_arm64.rpm", "202a1c36f8300a8a3b3603fa2b9c316cefd582afb2c6f6020e49577256d84c3d"},
	} {
		t.Run(item.format, func(t *testing.T) {
			if (item.format == "pkg") != (runtime.GOOS == "darwin") {
				t.Skip("different native package platform")
			}
			file := filepath.Join(root, item.name)
			verify := func() {
				reader, err := os.Open(file)
				require.NoError(t, err)
				hash := sha256.New()
				_, err = io.Copy(hash, reader)
				closeErr := reader.Close()
				require.NoError(t, err)
				require.NoError(t, closeErr)
				require.Equal(t, item.hash, hex.EncodeToString(hash.Sum(nil)))
			}
			verify()
			p := metadataDescriptor(item.format)
			inspect := inspectLinux
			if item.format == "pkg" {
				inspect = func(ctx context.Context, file string, p packageapi.Package, _ packageReader) error {
					reader, err := os.Open(file)
					if err != nil {
						return err
					}
					defer reader.Close()
					info, err := reader.Stat()
					if err != nil {
						return err
					}
					return inspectMacArchive(ctx, reader, info.Size(), p)
				}
			}
			require.NoError(t, inspect(t.Context(), file, p, readNativePackage))
			p.Architecture = "amd64"
			require.ErrorIs(t, inspect(t.Context(), file, p, readNativePackage), ErrMetadata)
			verify()
		})
	}
}
