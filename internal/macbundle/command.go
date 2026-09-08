package macbundle

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
)

const usage = `Usage: openuem-macos-bundle -agent <absolute executable> -output <absolute private directory>
       -version <major.minor.patch> -build <1..9999> -architecture <amd64|arm64>

Assemble OpenUEM Agent.app for macOS 13 or later in an existing private build
directory. Use a trusted build workspace with trusted ancestor directories.
The input must be a single-architecture 64-bit Mach-O executable matching the
requested target. Existing output is rejected without replacement. The source
executable is retained and verified while copying; it is never modified.

The bundle contains public code and sealed-at-signing app/service metadata only.
It carries no invitation, organization configuration, private key or device identity.
The service definition uses /Library/OpenUEMAgent/identity for completed enrollment.
No installation, service registration, signing, notarization or network access occurs.

Sign the completed app with Developer ID before computing its agent size/hash.
Then package, sign and notarize through the authorized release pipeline. Do not use
a pre-signing executable hash in a release manifest: signing may change its bytes.
The result always reports requires_release_signing: true. It is not an approved
installer or evidence of successful service activation. macOS service registration,
required administrator approval and final installer integration are separate steps.
`

func Command(ctx context.Context, args []string, output, diagnostics io.Writer) int {
	return command(ctx, args, output, diagnostics, Build)
}

func command(ctx context.Context, args []string, output, diagnostics io.Writer, build func(context.Context, Options) (Result, error)) int {
	if ctx == nil || output == nil || diagnostics == nil {
		return 2
	}
	flags := flag.NewFlagSet("openuem-macos-bundle", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var o Options
	seen := map[string]bool{}
	textFlag := func(name string, target *string) {
		flags.Func(name, "", func(value string) error {
			if seen[name] {
				return ErrOptions
			}
			seen[name] = true
			*target = value
			return nil
		})
	}
	textFlag("agent", &o.Agent)
	textFlag("output", &o.Output)
	textFlag("version", &o.Version)
	textFlag("architecture", &o.Architecture)
	var buildText string
	textFlag("build", &buildText)
	err := flags.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		if _, err := io.WriteString(output, usage); err != nil {
			return 1
		}
		return 0
	}
	// Keep the build number canonical, bounded and valid for CFBundleVersion.
	if len(buildText) >= 1 && len(buildText) <= 4 && buildText[0] != '0' {
		for _, digit := range buildText {
			if digit < '0' || digit > '9' {
				o.Build = 0
				break
			}
			o.Build = o.Build*10 + int(digit-'0')
		}
	}
	if err != nil || len(args) > 10 || flags.NArg() != 0 || !validOptions(o) {
		fmt.Fprintln(diagnostics, ErrOptions)
		return 2
	}
	result, err := build(ctx, o)
	if result.Published {
		if writeErr := json.NewEncoder(output).Encode(result); writeErr != nil {
			fmt.Fprintln(diagnostics, "The draft app bundle was published, but its result could not be written.")
			return 1
		}
	}
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(diagnostics, "Bundle assembly was canceled; inspect the private output directory before retrying.")
		return 130
	}
	message := ErrBuild
	for _, known := range []error{ErrOptions, ErrUnsupported, ErrSource, ErrOutput, ErrExists, ErrBuild, ErrDurability} {
		if errors.Is(err, known) {
			message = known
			break
		}
	}
	fmt.Fprintln(diagnostics, message)
	return 1
}
