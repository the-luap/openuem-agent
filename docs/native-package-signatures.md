# Native installer signature verification

`internal/packagesignature.Verify` adds the operating system's installer policy
check to the independently signed release/configuration protocol. It does not
install or execute the candidate and does not authorize an OpenUEM release by
itself. The bootstrap and updater must still integrate this check with release pins
and installation acceptance. [Protected package staging](bootstrap-package-staging.md)
now joins native verification to exact-origin downloads, file hashes and checkpoints.

Candidates must be regular, nonempty files of at most 512 MiB, with the exact
supported extension (`exe`/`msi` on Windows, `pkg` on macOS). The immediate staging
directory and file must have private ownership/access controls. Final symlinks,
noncanonical/control-containing paths and Windows UNC/device paths are rejected.
The caller must keep every ancestor protected, hold the verified file and check
the release hash before and after native verification. Do not reopen or execute a
replaceable path after those checks. `keyfile.Open` provides a bounded, protected
streaming descriptor without allocating an installer-sized buffer.

On Windows, the installed agent dispatches an internal read-only helper before
logger, identity or service startup. The helper opens the candidate without
write/delete sharing and supplies its descriptor to `WinVerifyTrustEx` using the
Authenticode policy, no UI, revocation checks, disabled MD2/MD4 and web-download
policy. Only a zero trust result succeeds; provider state is closed even on error.
The parent runs the same installed executable and kills/joins it on cancellation
or a two-minute deadline. This bounds a stalled native trust-provider call.
See Microsoft's [trust API](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust),
[policy options](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data)
and [opened-file contract](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info).

On macOS, verification invokes the absolute system `spctl` executable with an
installation assessment, disabled assessment-cache reuse/publication and an English
environment. It requires both successful exit and exactly one documented
`source=Notarized Developer ID` result. A local exception, Apple System signature
or unnotarized Developer ID does not satisfy this check. It never changes Gatekeeper
policy, removes quarantine or imports a certificate. The same two-minute deadline
and process join apply. Apple explains the notarization source in
[WWDC19: All About Notarization](https://developer.apple.com/videos/play/wwdc2019/703/).

Diagnostics are capped at 16 KiB, discarded after checking and never exposed in
errors or logs. Failed checks return a generic signature error; caller cancellation
is preserved. No offline bypass, self-signed exception or unsigned fallback exists.
Unavailable revocation/notarization services can therefore prevent acceptance.

Tests cover real subprocess cancellation/output bounds, private file/route limits,
unsigned data and malformed helper invocations. Windows CI copies the Go project's
existing EV-signed test executable solely as verification data, checks it, modifies
its signed bytes and requires rejection. A copied catalog-signed Windows system
file is unsuitable as an embedded-signature fixture. macOS creates an isolated unsigned installer
with a non-executable text payload and requires native rejection; it is never
installed. No workstation trust settings or signing credentials are changed.
An actual OpenUEM Authenticode release and Developer-ID-signed, notarized package
still require release credentials and separate installation/device acceptance.

Agent `fddf331` passed [Windows, macOS and Linux CI](https://github.com/the-luap/openuem-agent/actions/runs/34190495485),
including the unchanged native trust policy, embedded-signature acceptance and
mutation rejection, isolated Keychain/DPAPI tests and full agent builds.
