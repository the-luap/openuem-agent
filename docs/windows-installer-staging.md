# Protected Windows installer staging

`windowssoftware.Stage` prepares an artifact from an already authenticated MSI/EXE/Burn
plan. It does not execute the artifact. The individual Windows service now uses
it through the [native executor](windows-installer-processes.md) after exclusive
durable task admission. The console separately authorizes
[dispatch and read-only reconciliation](windows-software-delivery.md).

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

Close removes only the original file and directory. Native deletion can fail while
Windows retains an open handle or mapping; see Microsoft's
[DeleteFile contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew).
Cleanup now retries recognized Windows sharing, mapping and access failures under
one two-second deadline, including after execution cancellation. Every attempt
checks the original file identity again. A nonempty original directory can be
retried within the same bound; its unexpected contents are never recursively
removed. Other errors or replacement identities fail immediately. Repeated Close
calls retain the original sanitized failure and cannot reopen the candidate.
Cleanup does not queue deletion at reboot or extend the native process deadline.
An interrupted process or persistent cleanup failure can leave private staging data;
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

The [Burn layout reader](windows-burn-inspection.md) locates a bounded UX cabinet
and validates the embedded registration. Native Burn preflight binds its bundle
code, exact version, architecture, machine scope and registry view to the approved
plan before the [owned native executor](windows-installer-processes.md) starts it.

The original intermittent cleanup failure is reproduced by the owned AMD64 Burn
cancellation fixture at `d093e39`: Windows returned error `5` for the candidate
and `32` for its directory after the native process boundary returned. The fixture
records only the entry type and numeric error, never paths or installer output.
The new deterministic native tests hold real file/directory handles, require
joined removal after their release, preserve an administrator's replacement
between attempts, and bound permanent contention. Portable tests retain cleanup
errors and protect unexpected children. At `9f2a102`, these checks and all three
owned Burn installation/removal, cancellation and unfinished-child repetitions
pass on [AMD64 with the race detector](https://github.com/the-luap/openuem-agent/actions/runs/34633746056/job/103376552064)
and [native ARM64](https://github.com/the-luap/openuem-agent/actions/runs/34633746056/job/103376552000).
The ARM64 run actually encounters a directory sharing violation during its second
cancellation, retries successfully and still proves an empty staging root. Both
architectures bound permanent contention to 2.02 seconds and preserve replacements.
