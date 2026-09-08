// Package runtimeoptions selects an enrolled service without copying invitation
// tokens, device keys or mutable environment settings into its command line.
package runtimeoptions

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/open-uem/openuem-agent/internal/nativepath"
)

type Options struct {
	IdentityDirectory string
}

const usage = `Usage: openuem-agent serve -identity-directory <absolute protected path>

Run the Windows/macOS service using an existing individual device identity.
Configure these arguments in the operating system's protected service definition.
Windows runs through Service Control Manager as Local System; macOS runs through
launchd as root. The directory must contain completed enrollment from this same
installed agent. An invitation or pending enrollment cannot start the service.

The path is the only enrollment-related service argument. No invitation, private
key, server override, release override or trust bypass is accepted here. Explicit
serve arguments take precedence over legacy enrollment environment variables.
The existing installer-owned operational INI must also be present.

This command runs a registered service. It does not register a service, enroll a
new device, repeat an expired invitation or prove that the computer is online.
Use enroll -help for initial enrollment. Running with no arguments preserves the
existing service/environment selection.
`

type onceString struct {
	value string
	set   bool
}

func (v *onceString) String() string { return v.value }
func (v *onceString) Set(value string) error {
	if v.set {
		return errors.New("duplicate option")
	}
	v.value, v.set = value, true
	return nil
}

// Read returns whether the caller should start the service, or an exit code for
// help/invalid input. Call before initializing the logger or opening credentials.
// Parser diagnostics are suppressed so unknown arguments never echo secrets.
func Read(args []string, output, diagnostics io.Writer) (Options, bool, int) {
	if output == nil || diagnostics == nil {
		return Options{}, false, 2
	}
	if len(args) == 0 {
		return Options{}, true, 0
	}
	invalid := func() (Options, bool, int) {
		fmt.Fprintln(diagnostics, "Invalid service arguments; use serve -help for usage.")
		return Options{}, false, 2
	}
	if args[0] != "serve" || len(args) > 8 {
		return invalid()
	}
	var directory onceString
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Var(&directory, "identity-directory", "")
	err := flags.Parse(args[1:])
	if errors.Is(err, flag.ErrHelp) {
		if _, err := io.WriteString(output, usage); err != nil {
			return Options{}, false, 1
		}
		return Options{}, false, 0
	}
	if err != nil || flags.NArg() != 0 || !directory.set || !nativepath.Valid(directory.value) {
		return invalid()
	}
	return Options{IdentityDirectory: directory.value}, true, 0
}
