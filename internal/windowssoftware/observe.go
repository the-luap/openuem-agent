// Package windowssoftware reads exact machine software state independently of
// installer output. It does not authorize, install or remove a package.
package windowssoftware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var ErrObservation = errors.New("exact Windows software state could not be read")

const (
	helperArgument     = "--openuem-observe-windows-software"
	maxMessage         = 4096
	observationTimeout = 10 * time.Second
	Present            = "present"
	Absent             = "absent"
	Unknown            = "unknown"
)

// Rule follows the approved catalog's machine detection fields. Version is the
// exact expected reported version, which can differ from the package version.
type Rule struct {
	Kind         string `json:"kind"`
	ProductCode  string `json:"product_code,omitempty"`
	UninstallKey string `json:"uninstall_key,omitempty"`
	RegistryView string `json:"registry_view,omitempty"`
	Version      string `json:"version"`
}

type Observation struct {
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
}

func validText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

func (r Rule) Validate() error {
	if !validText(r.Version, 128) {
		return ErrObservation
	}
	switch r.Kind {
	case "msi-product":
		id, err := uuid.Parse(strings.TrimSuffix(strings.TrimPrefix(r.ProductCode, "{"), "}"))
		if err != nil || id == uuid.Nil || r.ProductCode != "{"+strings.ToUpper(id.String())+"}" || r.UninstallKey != "" || r.RegistryView != "" {
			return ErrObservation
		}
	case "uninstall-key":
		if !validText(r.UninstallKey, 255) || strings.ContainsAny(r.UninstallKey, `\/`) || r.ProductCode != "" || (r.RegistryView != "32" && r.RegistryView != "64") {
			return ErrObservation
		}
	default:
		return ErrObservation
	}
	return nil
}

func (o Observation) valid() bool {
	return (o.State == Present && validText(o.Version, 128)) || (o.State == Absent && o.Version == "")
}

// Matches describes only this observation. Callers still have to bind fresh
// observations to the authenticated operation and preserve restart uncertainty.
func (o Observation) Matches(r Rule) bool {
	return r.Validate() == nil && o.valid() && o.State == Present && o.Version == r.Version
}

// Observe invokes the same installed agent as a read-only helper before service
// startup. A private pipe carries the rule; no installer or shell is launched.
// The ten-second deadline bounds native calls, and cancellation joins the helper.
func Observe(ctx context.Context, r Rule) (Observation, error) {
	if ctx == nil || r.Validate() != nil {
		return Observation{State: Unknown}, ErrObservation
	}
	if err := ctx.Err(); err != nil {
		return Observation{State: Unknown}, err
	}
	ctx, cancel := context.WithTimeout(ctx, observationTimeout)
	defer cancel()
	return observeNative(ctx, r)
}

// HandleHelper runs before logger, enrollment identity and service initialization.
// It accepts only a canonical bounded rule and emits only a bounded observation.
func HandleHelper(args []string) (bool, int) {
	if len(args) == 0 || args[0] != helperArgument {
		return false, 0
	}
	if len(args) != 1 {
		return true, 1
	}
	// The read-only helper owns its deadline even if the parent crashes before
	// cancelling it. It never spawns children or starts installer operations.
	deadline := time.AfterFunc(observationTimeout, func() { os.Exit(1) })
	defer deadline.Stop()
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxMessage+1))
	defer clear(data)
	var r Rule
	if err != nil || !decodeMessage(data, &r) || r.Validate() != nil {
		return true, 1
	}
	o, err := readNative(r)
	if err != nil || !o.valid() {
		return true, 1
	}
	data, err = json.Marshal(o)
	if err != nil {
		return true, 1
	}
	if _, err = os.Stdout.Write(data); err != nil {
		return true, 1
	}
	return true, 0
}

// These messages are private parent/child protocol, not a public JSON API.
// Canonical comparison rejects duplicate, unknown and case-aliased fields.
func decodeMessage(data []byte, value any) bool {
	if len(data) == 0 || len(data) > maxMessage || !utf8.Valid(data) || json.Unmarshal(data, value) != nil {
		return false
	}
	canonical, err := json.Marshal(value)
	return err == nil && bytes.Equal(data, canonical)
}

type boundedOutput struct {
	data     []byte
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := maxMessage - len(b.data)
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil
}

func runObservation(ctx context.Context, command *exec.Cmd, r Rule) (Observation, error) {
	unknown := Observation{State: Unknown}
	data, err := json.Marshal(r)
	if err != nil {
		return unknown, ErrObservation
	}
	defer clear(data)
	var output boundedOutput
	command.Stdin = bytes.NewReader(data)
	command.Stdout = &output
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	err = command.Run()
	defer clear(output.data)
	if ctx.Err() != nil {
		return unknown, ctx.Err()
	}
	var o Observation
	if err != nil || output.overflow || !decodeMessage(output.data, &o) || !o.valid() {
		return unknown, ErrObservation
	}
	return o, nil
}

type msiQuery func(product, property string) (string, uint32)

func observeMSI(product string, query msiQuery) (Observation, error) {
	unknown := Observation{State: Unknown}
	state, code := query(product, "State")
	if code == 1605 {
		return Observation{State: Absent}, nil
	} // ERROR_UNKNOWN_PRODUCT
	if code != 0 || state != "5" {
		return unknown, ErrObservation
	}
	version, code := query(product, "VersionString")
	if code != 0 || !validText(version, 128) {
		return unknown, ErrObservation
	}
	state, code = query(product, "State")
	if code != 0 || state != "5" {
		return unknown, ErrObservation
	}
	return Observation{State: Present, Version: version}, nil
}
