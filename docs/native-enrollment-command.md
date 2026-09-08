# Native enrollment command

The installed Windows/macOS agent handles `enroll` before creating a logger or
starting its service. The command joins independently authorized bootstrap data,
native installer trust, the installed executable's signed byte binding and native
protected identity storage. It does not execute the downloaded installer or
activate the service. A finished end-user installer, release signing/provisioning
pipeline and service activation/recovery remain required integration work.

Run `openuem-agent enroll -help` for the complete English usage. On Windows invoke
the installed `openuem-agent.exe`; on macOS invoke the installed agent binary.
Use root on macOS or an elevated administrator on Windows. On macOS the same
installed executable must create and later read its System keychain identity.

## Provisioning and authorization

The trusted installer or administrator must supply:

- An independently authorized canonical HTTPS `-origin`, `-tenant-id` and
  `-site-id`. Neither an invitation URL nor its downloaded configuration can
  select these authorizations on its own.
- A private `-release-keys-file` containing one to eight distinct Ed25519 PKIX
  `PUBLIC KEY` PEM blocks, from the independent release pipeline. Private keys,
  skipped/malformed blocks, duplicate keys and files larger than 8 KiB are rejected.
- A private `-invitation-file` containing only the canonical limited invitation,
  optionally followed by one LF or CRLF. The maximum file size is 64 bytes.
  There is no command-line invitation-token argument.
- Absolute canonical `-identity-directory` and distinct `-staging-directory`
  paths below trusted administrator-controlled parents. Parents must already
  exist. Existing unsafe permissions are rejected without repair. Windows uses
  local drive paths; administrators must ensure they are not mapped network drives.
- `-accept-management`, explicitly authorizing inventory collection and
  administrator management actions for the selected organization/site. This is
  an administrator deployment interface; a guided end-user consent screen is
  separate outstanding installer work.

Input files must have private ownership/permissions for the invoking privileged
account. The generic protected-file policy does not accept a regular user's token
file merely because root can read it. Installer elevation must securely provision
the privileged input; no automatic permission changes or user-file handoff occurs.
The command rejects final input symlinks. Trusted ancestors remain an installation
requirement; these checks cannot secure an attacker-controlled parent directory.

Optional `-device-name` defaults to the empty name. Set it explicitly when needed
and keep it unchanged on retry. The command does not substitute the current
hostname, which could change between attempts and conflict with durable pending
state. No configuration or trust values are inferred from environment variables.

## Admission sequence

The command retains the actual executable before network work and opens the native
identity store before accessing the enrollment service. It reads the protected
release checkpoint, creates/checks the private staging root, then uses system-root
HTTPS to fetch the exact origin's bootstrap keys and invitation configuration.
There is no insecure-TLS, alternate-root, proxy or native-verification bypass flag.
The dedicated configuration signature and independently pinned release signature
must both verify. The authenticated invitation must equal the exact requested
token; organization/site IDs and the running native platform/architecture must
also match. A mismatch prevents package download and identity issuance.

The installed image must match the separately signed `agent_size`/`agent_sha256`.
Preview releases without that binding fail. The exact approved installer is then
downloaded into private staging and checked by the existing bounded native
Authenticode or notarized Developer ID verifier. The running executable and
staged package remain open until enrollment finishes.

`Store.EnrollInstalled` additionally requires a non-nil admission callback and a
signed executable binding. It checks admission before generating pending keys,
immediately before claiming, and after response validation immediately before
identity publication. Returning an already stored identity also rechecks admission.
The command's callback verifies both retained files and the latest checkpoint read
before entering the store. It does not call store methods recursively while the
store holds its lifetime lock. Existing exclusive pending publication still rejects
a competing different bootstrap rather than replacing its keys or scope.

A failed check after server issuance leaves pending keys intact. Repeating the
same command can recover with those exact keys while the invitation/configuration
remains valid. There are no automatic retries or state deletion. Expired/revoked
invitations, certificate renewal and re-enrollment need their separate recovery
workflows. Activating an already ready identity after invitation expiry must load
protected state directly rather than claiming again; activation is not implemented
by this command.

The overall context is limited to 20 minutes, in addition to the narrower HTTP,
download and native-verifier deadlines. Ctrl-C cancels the command. Resources are
closed in reverse order and only this operation's owned staged package is removed.
Private input files and durable identity records are retained. As with staging,
an abrupt process/OS crash can leave protected temporary data for later recovery.

## Output and verification

Success writes one JSON object with `identity_ready`, public device/organization/
site metadata and release version/digest. It contains no invitation, certificate
private key, NKey seed or configuration envelope. `identity_ready` means credentials
are persisted, not that a service is running or the endpoint has reported online.
Diagnostics never echo invalid arguments or raw native/network/storage errors.
Invalid arguments return exit 2; cancellation returns 130; other failures return 1.

If resource cleanup fails after persistence, the public success object is still
written, followed by a generic error on stderr and nonzero exit status. A failed
stdout write explicitly reports that enrollment finished but its result could not
be written. Neither condition implies the protected identity was rolled back.

Tests cover real HTTP/2 TLS configuration/package downloads, independent signature
trust, exact token/scope, invalid consent, changed bytes/checkpoints, cancellation,
resource closure and output redaction. Store tests separately cross every admission
boundary, including successful server issuance followed by local rejection and
same-key recovery. Windows CI also joins the real running test executable, the
licensed Go EV-signed fixture, real WinTrust, actual HTTPS certificate issuance and
machine-DPAPI storage, then verifies retry uses the persisted identity without a
second claim. Test packages are never installed or executed. macOS CI uses only an
isolated test keychain; positive notarized OpenUEM release acceptance and physical
endpoint installation still require the real signing credentials and devices.
