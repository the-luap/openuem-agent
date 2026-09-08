package enrollcommand

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
)

const usage = `Usage: openuem-agent enroll [options]

Enroll the installed Windows/macOS agent into an authorized organization/site.
Run as root on macOS or an elevated administrator on Windows. Provision all
paths below trusted administrator-controlled parents before running this command.

  -origin https://uem.example.com       Independently authorized public origin
  -tenant-id 1                         Authorized organization ID
  -site-id 2                           Authorized site ID
  -invitation-file <absolute path>      Private file containing the limited invitation
  -release-keys-file <absolute path>    Private PEM file with trusted Ed25519 public keys
  -identity-directory <absolute path>   Native protected credential directory
  -staging-directory <absolute path>    Private temporary package directory
  -device-name <name>                   Optional stable name; keep unchanged on retry
  -accept-management                   Authorize inventory collection and administrator
                                       management actions for the selected organization/site

The installed agent and downloaded installer must match the approved signed
release. Native installer verification uses Authenticode or notarized Developer ID.
The invitation is read from its file, never from a command-line token argument.
Successful output means credentials are ready. Service activation is separate.
Retain the original invitation and protected state if a retry is needed.
`

// Handle dispatches only the explicit enroll command, before service startup or
// logging. Unknown flags/values are never echoed; they could contain credentials.
func Handle(ctx context.Context, args []string, output, diagnostics io.Writer) (bool, int) {
	return handle(ctx, args, output, diagnostics, Run)
}

func handle(ctx context.Context, args []string, output, diagnostics io.Writer, runner func(context.Context, Options) (Result, error)) (bool, int) {
	if len(args) == 0 || args[0] != "enroll" {
		return false, 0
	}
	if ctx == nil || output == nil || diagnostics == nil {
		return true, 2
	}
	var options Options
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.Origin, "origin", "", "")
	flags.IntVar(&options.TenantID, "tenant-id", 0, "")
	flags.IntVar(&options.SiteID, "site-id", 0, "")
	flags.StringVar(&options.InvitationFile, "invitation-file", "", "")
	flags.StringVar(&options.ReleaseKeysFile, "release-keys-file", "", "")
	flags.StringVar(&options.IdentityDirectory, "identity-directory", "", "")
	flags.StringVar(&options.StagingDirectory, "staging-directory", "", "")
	flags.StringVar(&options.DeviceName, "device-name", "", "")
	flags.BoolVar(&options.AcceptManagement, "accept-management", false, "")
	err := flags.Parse(args[1:])
	if errors.Is(err, flag.ErrHelp) {
		if _, err := io.WriteString(output, usage); err != nil {
			return true, 1
		}
		return true, 0
	}
	if err != nil || flags.NArg() != 0 || !validOptions(options) {
		fmt.Fprintln(diagnostics, ErrOptions.Error()+"; use enroll -help for usage")
		return true, 2
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	result, err := runner(ctx, options)
	if result.IdentityReady {
		if writeErr := json.NewEncoder(output).Encode(result); writeErr != nil {
			fmt.Fprintln(diagnostics, "Enrollment finished, but its public result could not be written.")
			return true, 1
		}
	}
	if err != nil {
		message, code := safeDiagnostic(err)
		fmt.Fprintln(diagnostics, message)
		return true, code
	}
	return true, 0
}

func safeDiagnostic(err error) (string, int) {
	if errors.Is(err, context.Canceled) {
		return "Enrollment was canceled; retain the original invitation and protected state for recovery.", 130
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Enrollment timed out; retain the original invitation and protected state for recovery.", 1
	}
	for _, known := range []error{ErrOptions, ErrKeys, ErrInvitation, ErrExecutable, ErrStorage, ErrConfiguration, ErrScope, ErrPackage, ErrEnrollment, ErrCleanup} {
		if errors.Is(err, known) {
			return known.Error(), 1
		}
	}
	return ErrEnrollment.Error(), 1
}
