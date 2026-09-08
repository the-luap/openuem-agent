package packagesignature

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestMain(m *testing.M) {
	if handled, code := HandleHelper(os.Args[1:]); handled {
		os.Exit(code)
	}
	if len(os.Args) == 3 && os.Args[1] == "openuem-signature-process-fixture" {
		switch os.Args[2] {
		case "pass":
			fmt.Fprint(os.Stdout, "verified\n")
		case "overflow":
			fmt.Fprint(os.Stdout, strings.Repeat("x", maxDiagnosticSize+1))
		case "error":
			fmt.Fprint(os.Stderr, "private fixture diagnostic")
			os.Exit(2)
		case "wait":
			time.Sleep(time.Minute)
		default:
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestVerificationSubprocessBoundsOutputAndJoinsCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"pass", "overflow", "error", "wait"} {
		t.Run(mode, func(t *testing.T) {
			duration := 10 * time.Second
			if mode == "wait" {
				duration = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "openuem-signature-process-fixture", mode)
			data, err := runCheck(ctx, command)
			defer clear(data)
			if command.ProcessState == nil {
				t.Fatal("verification child was not joined")
			}
			switch mode {
			case "pass":
				if err != nil || string(data) != "verified\n" {
					t.Fatal("valid helper result lost", err)
				}
			case "wait":
				if !errors.Is(err, context.DeadlineExceeded) || data != nil {
					t.Fatal("verification did not cancel", err)
				}
			default:
				if !errors.Is(err, ErrUntrusted) || data != nil {
					t.Fatal("unsafe helper response accepted", err)
				}
			}
			if err != nil && strings.Contains(err.Error(), "private fixture") {
				t.Fatal("native diagnostic escaped")
			}
		})
	}
}

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := keyfile.CreateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestNativeSignatureRejectsUnsafeCandidatesAndUnsignedFiles(t *testing.T) {
	format := "exe"
	if runtime.GOOS == "darwin" {
		format = "pkg"
	}
	directory := privateTestDirectory(t)
	path := filepath.Join(directory, "unsigned."+format)
	if err := keyfile.Create(path, []byte("isolated unsigned non-executable fixture")); err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), path, format); !errors.Is(err, ErrUntrusted) {
		t.Fatal("unsigned candidate was accepted", err)
	}
	for _, candidate := range []string{"", "relative." + format, path + "\n", filepath.Join(directory, "missing."+format), directory, filepath.Join(directory, "child") + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(path)} {
		if err := Verify(context.Background(), candidate, format); !errors.Is(err, ErrUntrusted) {
			t.Fatal("unsafe path accepted", err)
		}
	}
	if err := Verify(context.Background(), path, "unknown"); !errors.Is(err, ErrUntrusted) {
		t.Fatal("unknown format accepted", err)
	}
	if err := Verify(nil, path, format); !errors.Is(err, ErrUntrusted) {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Verify(ctx, path, format); !errors.Is(err, context.Canceled) {
		t.Fatal("lost prior cancellation", err)
	}
	if runtime.GOOS != "windows" {
		alias := filepath.Join(directory, "alias."+format)
		if err := os.Symlink(path, alias); err != nil {
			t.Fatal(err)
		}
		if err := Verify(context.Background(), alias, format); !errors.Is(err, ErrUntrusted) {
			t.Fatal("symlink accepted", err)
		}
		if err := os.Chmod(directory, 0755); err != nil {
			t.Fatal(err)
		}
		if err := Verify(context.Background(), path, format); !errors.Is(err, ErrUntrusted) {
			t.Fatal("shared staging directory accepted", err)
		}
	}
	if handled, code := HandleHelper([]string{helperArgument}); !handled || code == 0 {
		t.Fatal("malformed helper invocation accepted")
	}
	if handled, _ := HandleHelper(nil); handled {
		t.Fatal("helper intercepted normal startup")
	}
}

func copySignatureFixture(t *testing.T, source, destination string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	data, err := io.ReadAll(io.LimitReader(input, 16<<20))
	if err != nil || len(data) == 16<<20 {
		t.Fatal("invalid native test fixture", err)
	}
	if err := keyfile.Create(destination, data); err != nil {
		t.Fatal(err)
	}
}
