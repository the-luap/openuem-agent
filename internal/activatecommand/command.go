package activatecommand

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/open-uem/openuem-agent/internal/nativepath"
)

const usage = `Usage: openuem-agent activate -identity-directory <absolute protected path>

Register and start the installed Windows agent using its completed enrollment.
Run as an elevated administrator from the installed signed agent executable.
The executable, installation directory and every ancestor must already belong
to the trusted installer. The installation directory and executable must be owned
by Local System or Administrators and must not allow other accounts to write.

The command creates private operational configuration and log directories under
the installed executable's directory, registers an automatic Local System service,
and waits up to two minutes for local service readiness. This starts inventory
collection and administrator management for the previously authorized enrollment.
It accepts no invitation, key, server override or service-name override.

Existing compatible configuration and the same service are reused. A foreign or
legacy service/configuration is rejected without replacement. Completed identity
state is retained on failure. Cancellation stops waiting; an already registered
service may continue starting. Inspect service status before retrying.

Running means the local service initialized; verify device connectivity in the
management console. macOS activation and signed installer integration are separate
work. Use enroll -help for initial enrollment and serve -help for service arguments.
`

type directoryFlag struct {
	value string
	set   bool
}

func (v *directoryFlag) String() string { return v.value }
func (v *directoryFlag) Set(value string) error {
	if v.set {
		return ErrOptions
	}
	v.value, v.set = value, true
	return nil
}

func Handle(ctx context.Context, args []string, output, diagnostics io.Writer) (bool, int) {
	return handle(ctx, args, output, diagnostics, Run)
}

func handle(ctx context.Context, args []string, output, diagnostics io.Writer, run func(context.Context, Options) (Result, error)) (bool, int) {
	if len(args) == 0 || args[0] != "activate" {
		return false, 0
	}
	if ctx == nil || output == nil || diagnostics == nil {
		return true, 2
	}
	flags := flag.NewFlagSet("activate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var directory directoryFlag
	flags.Var(&directory, "identity-directory", "")
	err := flags.Parse(args[1:])
	if errors.Is(err, flag.ErrHelp) {
		if _, err := io.WriteString(output, usage); err != nil {
			return true, 1
		}
		return true, 0
	}
	if err != nil || flags.NArg() != 0 || !directory.set || !nativepath.Valid(directory.value) {
		fmt.Fprintln(diagnostics, ErrOptions)
		return true, 2
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	result, err := run(ctx, Options{IdentityDirectory: directory.value})
	if result.Registered {
		if writeErr := json.NewEncoder(output).Encode(result); writeErr != nil {
			fmt.Fprintln(diagnostics, "Service registration finished, but its public result could not be written.")
			return true, 1
		}
	}
	if err == nil {
		return true, 0
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(diagnostics, "Activation waiting was canceled; retain the identity and inspect native service status before retrying.")
		return true, 130
	}
	message := ErrStart
	for _, known := range []error{ErrOptions, ErrUnsupported, ErrAccess, ErrIdentity, ErrConflict, ErrConfiguration, ErrRegistration, ErrStart, ErrCleanup} {
		if errors.Is(err, known) {
			message = known
			break
		}
	}
	fmt.Fprintln(diagnostics, message)
	return true, 1
}
