//go:build openuem_burn_test

package windowstest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

type BurnProcesses struct {
	Burn
	Payload, PIDs, Release string
}

// NewProcessBurn builds an owned payload that publishes its own and its child's
// PIDs, then waits for a private release file. It installs no application state.
// The child has no inherited output handles and exits after at most 90 seconds.
func NewProcessBurn(t *testing.T) BurnProcesses {
	t.Helper()
	wix := os.Getenv("OPENUEM_BURN_WIX")
	if !filepath.IsAbs(wix) {
		t.Fatal("owned Burn fixture requires the isolated pinned WiX tool")
	}
	root := t.TempDir()
	f := BurnProcesses{Payload: filepath.Join(root, "payload.exe"), PIDs: filepath.Join(root, "processes.json"), Release: filepath.Join(root, "release")}
	source := fmt.Sprintf(`package main
import ("encoding/json"; "os"; "os/exec"; "time")
func main() {
    if len(os.Args) == 2 && os.Args[1] == "child" { time.Sleep(90*time.Second); return }
    executable, err := os.Executable(); if err != nil { os.Exit(91) }
    child := exec.Command(executable, "child")
    if child.Start() != nil { os.Exit(92) }
    data, _ := json.Marshal([]uint32{uint32(os.Getpid()), uint32(child.Process.Pid)})
    if os.WriteFile(%q, data, 0600) != nil { _ = child.Process.Kill(); os.Exit(93) }
    deadline := time.Now().Add(90*time.Second)
    for time.Now().Before(deadline) {
        if _, err := os.Stat(%q); err == nil { return }
        time.Sleep(10*time.Millisecond)
    }
    _ = child.Process.Kill(); _ = child.Wait(); os.Exit(94)
}
`, f.PIDs, f.Release)
	if err := os.WriteFile(filepath.Join(root, "payload.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	runBurnTool(t, root, []string{"GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0"}, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", f.Payload, "payload.go")
	runBurnTool(t, root, nil, wix, "extension", "add", "WixToolset.Bal.wixext/4.0.6")
	bundle := `<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" xmlns:bal="http://wixtoolset.org/schemas/v4/wxs/bal">
  <Bundle Name="OpenUEM owned Burn process fixture" Manufacturer="OpenUEM test" Version="1.2.3.4" UpgradeCode="` + uuid.NewString() + `">
    <BootstrapperApplication><bal:WixStandardBootstrapperApplication LicenseUrl="" Theme="hyperlinkLicense" /></BootstrapperApplication>
    <Chain><ExePackage SourceFile="payload.exe" PerMachine="yes" Permanent="yes" DetectCondition="0" /></Chain>
  </Bundle>
</Wix>`
	if err := os.WriteFile(filepath.Join(root, "bundle.wxs"), []byte(bundle), 0600); err != nil {
		t.Fatal(err)
	}
	f.Burn = buildBurnFixture(t, root, wix, "amd64", "machine", "yes")
	return f
}
