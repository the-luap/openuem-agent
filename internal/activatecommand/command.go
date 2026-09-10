package activatecommand

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/open-uem/openuem-agent/internal/nativepath"
)

const usage = `Usage: openuem-agent activate -identity-directory <absolute protected path>

Register and start the installed Windows or macOS agent using its completed enrollment.
Run as an elevated administrator/root from the installed signed agent executable.
The executable, installation directory and every ancestor must already belong
to the trusted installer. This starts inventory collection and administrator
management for the previously authorized enrollment. No invitation, key, server
override or service-name override is accepted.

Windows: the executable and installation directory must be owned by Local System
or Administrators and must not allow other accounts to write. Private configuration
and log directories are created under the installed executable's directory. The
command registers an automatic Local System service and waits for authenticated
local readiness from that exact service process. SCM Running alone is insufficient
while the controller is recovering its identity. Cancellation leaves it stoppable.

macOS 13+: use /Applications/OpenUEM Agent.app/Contents/MacOS/openuem-agent and
-identity-directory /Library/OpenUEMAgent/identity. The final app must be root-owned,
signed with Developer ID Application and notarized. The sealed app/daemon metadata
must match the supported bundle layout. Operational configuration is prepared under
/Library/OpenUEMAgent/etc/openuem-agent and logs under /var/log/openuem-agent.
SMAppService registration may require administrator approval in System Settings >
General > Login Items. Allow OpenUEM Agent, then retry this command. A pending
approval returns public JSON with approval_required: true and exit status 3.
Readiness requires an authenticated local response from the enrolled daemon.

Existing compatible configuration and the same service are reused. Conflicting
configuration or service metadata causes an error. Completed identity
state is retained on failure. Cancellation stops waiting; an already registered
service may continue starting. Inspect service status before retrying. Waiting and
signature subprocesses have a two-minute context deadline; synchronous macOS
framework calls cannot be interrupted while executing.

Running means the local service initialized; verify device connectivity in the
management console. Signed installer distribution remains separate work. Use
enroll -help for initial enrollment and serve -help for service arguments.
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
	ctx, stop := activationContext(ctx)
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
	if errors.Is(err, ErrApproval) {
		fmt.Fprintln(diagnostics, ErrApproval)
		return true, 3
	}
	message := ErrStart
	for _, known := range []error{ErrOptions, ErrUnsupported, ErrAccess, ErrIdentity, ErrConflict, ErrConfiguration, ErrRegistration, ErrStart, ErrCleanup, ErrSignature} {
		if errors.Is(err, known) {
			message = known
			break
		}
	}
	fmt.Fprintln(diagnostics, message)
	return true, 1
}
