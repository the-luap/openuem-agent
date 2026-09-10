# Activate a completed Windows enrollment

The installed Windows agent now handles `activate` before logging or service
startup. It prepares operational configuration, registers the `openuem-agent`
automatic Local System service and waits up to two minutes for authenticated local
readiness from that exact service process. SCM `Running` alone is insufficient:
the controller also uses that state while identity recovery remains incomplete.
It loads the completed protected identity and never sends an invitation claim.
Run from an elevated administrator terminal:

```powershell
& 'C:\Program Files\OpenUEM Agent\openuem-agent.exe' activate `
  -identity-directory 'C:\ProgramData\OpenUEM\identity'
```

These are example paths; the trusted installer must provision the installed
executable and existing trusted parent directories. Run `activate -help` for
usage. The command starts inventory and management through the service associated
with the previously authorized enrollment. It is an administrator deployment
interface; a signed end-user installer and its consent UI remain separate work.
The same entry point has a separate [macOS activation flow](native-macos-activation.md).

## Admission and ownership

The command opens and retains its actual running executable, loads the native
DPAPI identity and checks the platform, architecture, certificate lifetime and
nonzero release checkpoint. The identity must contain the executable size and
SHA-256 admitted by `enroll`. The retained image is hashed again before each
configuration, registration and startup boundary and before reporting success.
The service independently checks this binding during `Agent.NewIndividual`.
An expired invitation or release envelope is unnecessary after completed
enrollment; the device certificate must still be valid.

The installation directory and executable must be owned by Local System or
Administrators and disallow writes by other accounts. Final reparse points are
rejected; the retained directory cannot be renamed while activation owns its
handle. Every ancestor must already be controlled by the trusted installer.
The command does not repair ownership or walk and secure untrusted ancestors.
Administrators must select a local installation; local drive syntax alone cannot
prove that a drive is not mapped to a network volume.

`config` and `logs` under the executable's directory must have private
System/Administrators access. Newly created directories and the operational INI
use protected DACLs. The INI is bounded to 32 KiB, marked `individual-v1` and tied
to the issued device UUID. It contains no private keys or invitations. Individual
mode disables SFTP and remote assistance. Existing compatible configuration is
preserved, including valid operational frequency changes. Legacy, foreign,
malformed, publicly accessible or ambiguously parsed configuration fails closed.
Publication is exclusive and never replaces an existing file.

The SCM definition uses the exact installed executable followed by `serve
-identity-directory <protected directory>`. Windows argument escaping preserves
spaces. Compatibility requires the same image path/arguments, own-process service
type, automatic startup, normal error control, Local System account, no service
dependencies/load-order group and no delayed startup. A differing existing service
is rejected without updating or deleting it. There is no service-name override,
alternate executable, server override, token argument or enrollment environment
dependency.

## Results and recovery

Successful registration writes public JSON containing `registered`, `running`,
`device_id`, `tenant_id` and `site_id`. `running` means a fresh signed local proof
confirms agent initialization and the same process is still running in SCM. It
does not prove broker connectivity or inventory delivery.
Verify those in the management console. Startup failure returns nonzero with
`registered: true, running: false` after a confirmed compatible registration.
Diagnostics omit raw native errors and invalid argument values.

Failure or Ctrl-C never deletes protected enrollment state or unregisters/stops
an already created service. Cancellation stops activation's waiting; a service
may continue starting. Inspect native service status, correct the reported local
problem and retry with the same installed executable and identity directory.
A stopped compatible service is started; an already running one is reused.
Abnormal process termination can leave an owned private temporary configuration
file. Automatic crash cleanup, installer rollback and uninstall are separate work.

Older protected records without the executable size/hash remain readable by the
existing explicitly configured runtime, but `activate` rejects them. Retrying
`EnrollInstalled` cannot silently add a binding to immutable old pending state or
replace its keys. An authorized migration is still required. Changing a bound
executable also prevents subsequent service startup until a separately authorized
release/binding update is implemented. Do not delete state or weaken verification
to work around either case. [Automatic certificate renewal](individual-identity-renewal.md)
and stoppable startup recovery are implemented; signed executable updates remain
outstanding. The [Windows readiness transport](windows-local-readiness.md) closes
and joins each generation's proof endpoint before its signing key is released.

## Verification scope

Portable tests cover admission ordering, partial results, cancellation, expiry,
configuration parsing and redacted command output. Store tests check persisted
bindings, malformed pairs and refusal to replace existing pending state.
Executable tests distinguish byte changes from stable paths, sizes and timestamps.

Windows CI copies its own test executable into private fixture directories,
creates actual HTTPS-issued DPAPI identities and closes the issuer before running
activation. Uniquely named SCM fixture services run as Local System and call the
actual individual agent constructor against that copied executable, its stored
binding and the generated operational configuration. They deliberately do not
start inventory, broker connections or host management. Tests exercise successful
activation/retry, preserved configuration and identity records, retained startup
failure and recovery, foreign service/configuration, unsafe DACLs and independent
runtime rejection of a wrong executable binding. Each fixture service is stopped
and deleted. Production has no service-name override.

The copied test executable is not a signed OpenUEM release or end-user installer.
Native enrollment's WinTrust acceptance is verified separately. These tests do
not establish signed installer integration, physical endpoint acceptance, reboot
recovery or remote online status. The implementation uses the existing native
[SCM creation contract](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)
and [service lifecycle](service-lifecycle.md).
