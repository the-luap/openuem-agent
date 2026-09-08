package runtimeoptions

import (
	"bytes"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type brokenOutput struct{}

func (brokenOutput) Write([]byte) (int, error) { return 0, errors.New("fixture output failed") }

func TestServiceSelectionUsesOnlyExplicitCanonicalDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "identity")
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "invalid")
	t.Setenv("OPENUEM_AGENT_IDENTITY_DIRECTORY", "untrusted environment")
	for _, args := range [][]string{{"serve", "-identity-directory", directory}, {"serve", "--identity-directory=" + directory}} {
		var output, diagnostics bytes.Buffer
		options, start, code := Read(args, &output, &diagnostics)
		if !start || code != 0 || options.IdentityDirectory != directory || output.Len() != 0 || diagnostics.Len() != 0 {
			t.Fatalf("explicit selection failed: %+v %v %d", options, start, code)
		}
	}
	var output bytes.Buffer
	options, start, code := Read(nil, &output, &output)
	if options.IdentityDirectory != "" || !start || code != 0 {
		t.Fatal("default invocation did not preserve existing selection")
	}
}

func TestServiceSelectionRejectsSecretsOverridesDuplicatesAndAliases(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "identity")
	secret := "fixture-secret-never-echo-this"
	cases := [][]string{
		{"unknown-" + secret}, {"serve"}, {"serve", "-identity-directory"},
		{"serve", "-identity-directory="}, {"serve", "-identity-directory", "relative"},
		{"serve", "-identity-directory", directory + string(filepath.Separator)},
		{"serve", "-identity-directory", directory + string(filepath.Separator) + ".."},
		{"serve", "-identity-directory", directory + "\n" + secret},
		{"serve", "-identity-directory", directory + "\x00" + secret},
		{"serve", "-identity-directory", directory + string([]byte{0xff})},
		{"serve", "-identity-directory", directory + strings.Repeat("a", 4096)},
		{"serve", "-identity-directory", directory, "-identity-directory", directory},
		{"serve", "-identity-directory", directory, secret},
		{"serve", "-identity-directory", directory, "-invitation", secret},
		{"serve", "-identity-directory", directory, "-origin", "https://" + secret + ".invalid"},
		{"serve", "-insecure=true"}, {"serve", "-" + secret},
		{"serve", "--", "-identity-directory", directory},
		{"serve", "-h", "1", "2", "3", "4", "5", "6", secret},
	}
	if runtime.GOOS == "windows" {
		for _, path := range []string{`\\server\share\identity`, `\\?\C:\identity`, `\\.\C:\identity`, `C:identity`} {
			cases = append(cases, []string{"serve", "-identity-directory", path})
		}
	}
	for _, args := range cases {
		var output, diagnostics bytes.Buffer
		options, start, code := Read(args, &output, &diagnostics)
		if start || code != 2 || options.IdentityDirectory != "" || output.Len() != 0 {
			t.Errorf("invalid service invocation admitted: %q", args[0])
		}
		if diagnostics.String() != "Invalid service arguments; use serve -help for usage.\n" || strings.Contains(diagnostics.String(), secret) {
			t.Fatal("parser echoed untrusted arguments")
		}
	}
}

func TestServiceHelpNeverStartsAndHandlesOutputFailure(t *testing.T) {
	for _, help := range []string{"-help", "-h", "--help"} {
		var output, diagnostics bytes.Buffer
		options, start, code := Read([]string{"serve", help}, &output, &diagnostics)
		if start || code != 0 || options.IdentityDirectory != "" || diagnostics.Len() != 0 || !strings.Contains(output.String(), "existing individual device identity") {
			t.Fatal("invalid help behavior")
		}
	}
	var diagnostics bytes.Buffer
	if _, start, code := Read([]string{"serve", "-help"}, brokenOutput{}, &diagnostics); start || code != 1 {
		t.Fatal("output failure hidden")
	}
	if _, start, code := Read(nil, nil, &diagnostics); start || code != 2 {
		t.Fatal("nil output accepted")
	}
}
