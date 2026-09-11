# Protected Windows installer staging

`windowssoftware.Stage` prepares an artifact from an already authenticated MSI/EXE
plan. It does not execute the artifact. The individual Windows service now uses
it through the [native executor](windows-installer-processes.md) after exclusive
durable task admission. Explicit console dispatch and reconciliation remain open.

The downloader uses a separate HTTPS transport with system server trust, no
enrollment client certificate, cookie jar, environment proxy or redirects. A
download cannot supply its own TLS trust. A private query token stays in the exact
approved URL and never enters returned errors or logs. The transport limits TLS
and dial setup to ten seconds, response headers to 25 seconds and 32 KiB, and the
whole download/signature stage to fifteen minutes or the earlier caller deadline.
Only complete HTTP 200, unencoded bytes are accepted; the body is streamed with
the 512 MiB installer ceiling and the approved SHA-256 digest.

Staging creates a random private directory under the caller's protected root,
then writes and synchronizes an exclusive private file. Windows retains a read
handle that excludes write/delete sharing, rejects reparse points and multiple
hard links, and names the exact original file. The same protected bytes are
hashed before and after the existing native Authenticode policy. The caller
keeps the object open and rechecks it immediately before native use. Approval,
SHA-256 and native signature validation are independent requirements.

Close removes only the original file and directory. It never recursively removes
an unexpected replacement. An interrupted process can leave private staging data;
such data is not an execution permit or a reason to repeat an installer attempt.
The immutable software journal remains the replay boundary.

Portable tests transfer only owned inert bytes over an isolated HTTPS server and
cover hash changes, incomplete/oversized/empty responses, encodings, redirects,
TLS failures, cancellation, native denial, post-check mutation and cleanup. The
Windows suite additionally requires the actual file-sharing checks and downloads
the existing [EV-signed Go fixture](../internal/packagesignature/testdata/README.md)
from that local server into the real Authenticode helper. A deliberately damaged
copy with its own matching SHA-256 must still fail native signature policy. Neither
copy is executed; no certificate is imported and OS trust is unchanged. These
checks are not physical package-installation acceptance.

The separate [Burn layout reader](windows-burn-inspection.md) locates a bounded
UX cabinet and section-declared bundle code without executing the package. It
does not yet establish embedded registration identity and is not wired into
native preflight or execution.
