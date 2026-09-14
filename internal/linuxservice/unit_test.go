package linuxservice

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestUnitRejectsUnboundPathsAndForeignDefinitions(t *testing.T) {
	s := Spec{Executable: "/usr/local/bin/openuem-agent", IdentityDirectory: "/var/lib/openuem-agent/identity"}
	data, err := Render(s)
	if err != nil || !Matches(data, s) {
		t.Fatal("canonical service definition rejected", err)
	}
	for _, changed := range [][]byte{
		append(bytes.Clone(data), []byte("\n[Service]\nExecStartPre=/usr/bin/foreign\n")...),
		bytes.ReplaceAll(data, []byte("User=root"), []byte("User=nobody")),
		bytes.ReplaceAll(data, []byte("serve -identity-directory"), []byte("enroll -invitation-file")),
		bytes.ReplaceAll(data, []byte("KillMode=mixed"), []byte("KillMode=process")),
		bytes.ReplaceAll(data, []byte("ExecStart=:"), []byte("ExecStart=")),
		bytes.ReplaceAll(data, []byte("openuem-agent/identity"), []byte("foreign/identity")),
		bytes.Repeat([]byte{'a'}, MaxUnitSize+1),
	} {
		if Matches(changed, s) {
			t.Fatal("foreign service metadata retained installation authority")
		}
	}
	for _, path := range []string{"", "/", "relative", "/var/../etc/identity", "/var//identity", "/var/identity/", "/var/identity\nExecStart=/usr/bin/foreign", "/var/identity\x00", "/var/\tidentity", "/var/\x7fidentity", "/var/" + strings.Repeat("a", 4096), string([]byte{'/', 0xff})} {
		for _, field := range []string{"executable", "identity"} {
			invalid := s
			if field == "executable" {
				invalid.Executable = path
			} else {
				invalid.IdentityDirectory = path
			}
			if data, err := Render(invalid); data != nil || !errors.Is(err, ErrUnit) {
				t.Fatal("unbound service path accepted", field)
			}
		}
	}
	for _, executable := range []string{s.IdentityDirectory, s.IdentityDirectory + "/agent", `/opt/agent"`, `/opt/agent'`, `/opt/agent\`} {
		invalid := s
		invalid.Executable = executable
		if _, err = Render(invalid); !errors.Is(err, ErrUnit) {
			t.Fatal("unsupported executable path was accepted")
		}
	}
}

func TestUnitQuotesLiteralSystemdPathArguments(t *testing.T) {
	s := Spec{Executable: `/opt/OpenUEM agent/agent%u`, IdentityDirectory: `/var/lib/OpenUEM $HOME/${USER}/"quoted"\identity%h`}
	data, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	want := `ExecStart=:"/opt/OpenUEM agent/agent%%u" serve -identity-directory "/var/lib/OpenUEM $HOME/${USER}/\"quoted\"\\identity%%h"` + "\n"
	if !bytes.Contains(data, []byte(want)) {
		t.Fatal("service path quoting lost literal arguments")
	}
}

func FuzzUnitLiteralPaths(f *testing.F) {
	f.Add("/usr/bin/openuem-agent", "/var/lib/openuem-agent/identity")
	f.Add("/opt/agent %u", "/var/lib/$HOME/identity")
	f.Add("/opt/agent\nExecStart=evil", "/var/identity")
	f.Fuzz(func(t *testing.T, executable, directory string) {
		s := Spec{Executable: executable, IdentityDirectory: directory}
		data, err := Render(s)
		if err != nil {
			return
		}
		if !s.Valid() || !Matches(data, s) || bytes.Count(data, []byte("\nExecStart=")) != 1 || len(data) > MaxUnitSize {
			t.Fatal("rendered service crossed its bounded single-command contract")
		}
	})
}
