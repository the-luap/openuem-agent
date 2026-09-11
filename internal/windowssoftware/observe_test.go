package windowssoftware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if handled, code := HandleHelper(os.Args[1:]); handled {
		os.Exit(code)
	}
	if len(os.Args) == 3 && os.Args[1] == "owned-observation-fixture" {
		data, _ := io.ReadAll(io.LimitReader(os.Stdin, maxMessage+1))
		var r Rule
		if !decodeMessage(data, &r) || r.Validate() != nil {
			os.Exit(9)
		}
		switch os.Args[2] {
		case "present":
			fmt.Fprint(os.Stdout, `{"state":"present","version":"1.2.3"}`)
		case "absent":
			fmt.Fprint(os.Stdout, `{"state":"absent"}`)
		case "different":
			fmt.Fprint(os.Stdout, `{"state":"present","version":"1.2.30"}`)
		case "overflow":
			fmt.Fprint(os.Stdout, strings.Repeat("x", maxMessage+1))
		case "error":
			fmt.Fprint(os.Stderr, "private native diagnostic")
			os.Exit(2)
		case "unknown":
			fmt.Fprint(os.Stdout, `{"state":"unknown"}`)
		case "partial":
			fmt.Fprint(os.Stdout, `{"state":"absent"`)
		case "duplicate":
			fmt.Fprint(os.Stdout, `{"state":"present","state":"absent"}`)
		case "wait":
			time.Sleep(time.Minute)
		default:
			os.Exit(8)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testRule() Rule {
	return Rule{Kind: "msi-product", ProductCode: "{AABBCCDD-0000-4000-8000-000000000001}", Version: "1.2.3"}
}

func TestSoftwareObservationRejectsAmbiguousRulesAndMessages(t *testing.T) {
	for _, change := range []func(*Rule){
		func(r *Rule) { r.Kind = "script" }, func(r *Rule) { r.ProductCode = strings.ToLower(r.ProductCode) },
		func(r *Rule) { r.ProductCode = "{00000000-0000-0000-0000-000000000000}" }, func(r *Rule) { r.RegistryView = "64" },
		func(r *Rule) { r.UninstallKey = "arbitrary" }, func(r *Rule) { r.Version = "" }, func(r *Rule) { r.Version = "1.2.3\n" },
		func(r *Rule) { r.Version = strings.Repeat("x", 129) }, func(r *Rule) { r.Version = "\xff" },
	} {
		r := testRule()
		change(&r)
		if r.Validate() == nil {
			t.Fatal("invalid rule accepted")
		}
	}
	r := Rule{Kind: "uninstall-key", UninstallKey: "Owned product", RegistryView: "32", Version: "1.2.3"}
	if r.Validate() != nil {
		t.Fatal("exact registry rule rejected")
	}
	for _, key := range []string{`..\Other`, "other/subkey", "", " padded", "line\nkey"} {
		r.UninstallKey = key
		if r.Validate() == nil {
			t.Fatal("arbitrary or ambiguous registry path accepted")
		}
	}
	for _, value := range []string{
		`{"state":"present","version":"1.2.3","extra":"private"}`, `{"State":"absent"}`,
		`{"state":"present","state":"absent"}`, `{"state":"absent"} {"state":"absent"}`,
		`null`, `{"state":"absent","version":"1.2.3"}`, `{"state":"present"}`, `{"state":"unknown"}`,
	} {
		var o Observation
		if decodeMessage([]byte(value), &o) && o.valid() {
			t.Fatal("unsafe observation accepted", value)
		}
	}
	data, _ := json.Marshal(testRule())
	var decoded Rule
	if !decodeMessage(data, &decoded) || decoded != testRule() {
		t.Fatal("canonical helper input lost")
	}
	long := Rule{Kind: "uninstall-key", UninstallKey: strings.Repeat("<", 255), RegistryView: "64", Version: strings.Repeat(">", 128)}
	data, _ = json.Marshal(long)
	var longDecoded Rule
	if long.Validate() != nil || !decodeMessage(data, &longDecoded) || longDecoded != long {
		t.Fatal("valid escaped detection rule exceeded the helper boundary")
	}
	if (Observation{State: Present, Version: "1.2.30"}).Matches(testRule()) || (Observation{State: Absent}).Matches(testRule()) || !(Observation{State: Present, Version: "1.2.3"}).Matches(testRule()) {
		t.Fatal("exact version evidence changed")
	}
}

func TestSoftwareObservationMSIUsesInstalledMachineEvidence(t *testing.T) {
	type result struct {
		value string
		code  uint32
	}
	for _, tc := range []struct {
		name    string
		results []result
		state   string
		fail    bool
	}{
		{"installed", []result{{"5", 0}, {"1.2.3", 0}, {"5", 0}}, Present, false},
		{"absent", []result{{"", 1605}}, Absent, false},
		{"advertised", []result{{"1", 0}}, Unknown, true},
		{"denied", []result{{"", 5}}, Unknown, true},
		{"corrupt", []result{{"", 1610}}, Unknown, true},
		{"missing_version", []result{{"5", 0}, {"", 1608}}, Unknown, true},
		{"removed_during_read", []result{{"5", 0}, {"1.2.3", 0}, {"", 1605}}, Unknown, true},
		{"advertised_during_read", []result{{"5", 0}, {"1.2.3", 0}, {"1", 0}}, Unknown, true},
		{"version_overflow", []result{{"5", 0}, {strings.Repeat("x", 129), 0}}, Unknown, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			o, err := observeMSI(testRule().ProductCode, func(product, property string) (string, uint32) {
				if product != testRule().ProductCode || calls >= len(tc.results) {
					t.Fatal("MSI query changed identity or exceeded bound")
				}
				want := "State"
				if calls == 1 {
					want = "VersionString"
				}
				if property != want {
					t.Fatal("queried unrelated MSI property")
				}
				r := tc.results[calls]
				calls++
				return r.value, r.code
			})
			if (err != nil) != tc.fail || o.State != tc.state || calls != len(tc.results) {
				t.Fatal("MSI evidence classification", o, err, calls)
			}
			if tc.fail && !errors.Is(err, ErrObservation) {
				t.Fatal("native diagnostic escaped", err)
			}
		})
	}
}

func TestSoftwareObservationChildIsBoundedJoinedAndRedacted(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"present", "absent", "different", "overflow", "error", "unknown", "partial", "duplicate", "wait"} {
		t.Run(mode, func(t *testing.T) {
			duration := 10 * time.Second
			if mode == "wait" {
				duration = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), duration)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "owned-observation-fixture", mode)
			o, err := runObservation(ctx, command, testRule())
			if command.ProcessState == nil {
				t.Fatal("helper process was not joined")
			}
			switch mode {
			case "present":
				if err != nil || !o.Matches(testRule()) {
					t.Fatal(o, err)
				}
			case "absent":
				if err != nil || o.State != Absent || o.Version != "" {
					t.Fatal(o, err)
				}
			case "different":
				if err != nil || o.State != Present || o.Matches(testRule()) {
					t.Fatal(o, err)
				}
			case "wait":
				if !errors.Is(err, context.DeadlineExceeded) || o.State != Unknown {
					t.Fatal(o, err)
				}
			default:
				if !errors.Is(err, ErrObservation) || o.State != Unknown || o.Version != "" {
					t.Fatal("unsafe helper result", o, err)
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if o, err := Observe(ctx, testRule()); !errors.Is(err, context.Canceled) || o.State != Unknown {
		t.Fatal("cancelled observation accepted", o, err)
	}
	if o, err := Observe(nil, testRule()); !errors.Is(err, ErrObservation) || o.State != Unknown {
		t.Fatal("nil context accepted", o, err)
	}
}

func TestSoftwareObservationHelperHasIndependentDeadline(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Keep the input pipe open. The helper must end itself without an EOF or
	// parent cancellation; this watchdog only prevents a broken test leaking it.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, helperArgument)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	started := time.Now()
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(testRule())
	if _, err = input.Write(data); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	err = command.Wait()
	if err == nil || ctx.Err() != nil || command.ProcessState == nil || command.ProcessState.ExitCode() != 1 || time.Since(started) < observationTimeout {
		t.Fatal("helper did not enforce its independent deadline", err, ctx.Err())
	}
}
