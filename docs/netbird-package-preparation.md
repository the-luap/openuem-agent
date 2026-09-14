# Protected NetBird Unix package preparation

`internal/netbirdinstall.Stage` prepares one exact organization-approved Unix
package in a private directory. It checks the shared descriptor's organization,
current native platform and architecture before network access. Sources, approval
identity, native package version, format, byte length and SHA-256 remain bound to
the descriptor's canonical digest. The caller must supply an already
authenticated, current approval and keep the staging root beneath protected
ancestors. Preparation itself is not command or execution authority.

Downloads use an independent HTTPS client with certificate verification, TLS
1.2 minimum, bounded dialing/headers, a five-minute overall preparation deadline
and the caller's earlier cancellation. They send neither an enrollment identity
nor provider credentials, cookies or environment proxy configuration. Redirects,
non-200 status, content encoding and incompatible content lengths are rejected.
Streaming reads stop at the approved size plus one byte, bounded by 512 MiB.
Bytes must exactly match the approved length and SHA-256 before native checks.

The private stage uses a random directory and a fixed `package.deb`, `package.rpm`
or `package.pkg` filename. Files are created through the protected keyfile helper,
synced and reopened with an owned read-only descriptor. Verification compares
directory and file identity, private permissions, exact descriptor and bytes.
The container prefix must match the declared format. On macOS the existing
[native signature verifier](native-package-signatures.md) must accept the PKG;
the same file is hashed again afterwards. This preserves Gatekeeper policy and
does not allow unsigned tarball extraction as a substitute for official PKGs.
The official [NetBird macOS documentation](https://docs.netbird.io/get-started/install/macos)
describes that signing distinction.

Preparation now also requires [native package identity](netbird-package-identity.md)
to match the descriptor. DEB/RPM queries compare the exact name, native version
and architecture. macOS checks the distribution, component receipt and the
architecture of both bundled executables using bounded reads from the retained
file. Linux metadata inspection does not independently authenticate the publisher.
Current approval provenance and identity must still be enforced at the eventual
execution boundary. No maintainer script, installer, filesystem archive extraction,
service action or provider call is performed by this preparation component.

`Prepared.Verify` rechecks the same file against the exact descriptor, including
its approval and organization; changing either invalidates the preparation.
`Prepared.Inspect` repeats that verification before and after native metadata
inspection while retaining exclusive ownership against concurrent cleanup.
Normal formatting and incidental JSON serialization hide private source data.
`Close` removes only the original stage file and directory and preserves a
replacement path. Concurrent verification and cleanup serialize on the owned
object. Callers must retain this object and protected parent through any future
execution and recheck current approval/recipient authority immediately before it.

The old, unreferenced platform `Install` and `Uninstall` functions have been
removed, including the Unix remote shell pipelines and the unpinned Windows
package calls. Existing legacy installer subscriptions still reject requests.
Windows retains its separately approved, authenticated software workflow.

## Verification and remaining integration

Owned TLS/filesystem fixtures cover formats, exact URLs and empty identity
headers, lengths, streaming bounds, hash/container mismatch, TLS and redirect
refusal, context expiry, private roots, replaced files/directories, changed
permissions, native-check mutation and concurrent cleanup. macOS also invokes the
real native verifier on inert unsigned PKG data and requires rejection; it never
installs or executes that data. The native preparation race suite passes in
1.738 seconds, with existing command and journal race suites in 2.597 and 6.883
seconds. The shared descriptor race suite passes in 1.389 seconds; its seeded
decoder fuzz run processes 1,776,528 inputs in 11.301 seconds.
Linux container race suites pass for preparation, commands and journal in
1.268, 1.427 and 4.294 seconds. Native service/broker NetBird race tests pass in
3.015 seconds, including rejection of legacy installer subscriptions.
An escaped source exceeding the wire envelope is rejected before creating a
stage or making a request. Full agent builds pass for Linux, macOS and Windows;
console Linux and worker Linux/Windows builds pass with the same shared pin.

The console now provides [organization approval storage and history](https://github.com/the-luap/openuem-console/blob/fc5a2ae12c5cb47b47e1ff453e2d84b8ee09f895/docs/netbird-package-approvals.md)
with encrypted sources, explicit review, current software authority, atomic audit
and permanent revocation. This remains an implementation component, not a completed
installer feature. The [version-three command and common journal](netbird-execution-journal.md)
now preserve the exact package and current individual recipient in an immutable
command digest; journal records omit the private source. The
[native macOS installer](netbird-native-installation.md) now consumes this owner
under atomic journal admission and verifies exact native resulting state.
Authenticated preparation is bound to the service as described below. Console
command/capability delivery must still recheck the current approval and retain
durable attempts. Local removal and console uncertainty recovery need integration. Read-only checks of exact official v0.78.1 artifacts now pass;
physical/native installation acceptance remains separate from those checks.

## Authenticated service ownership

`NewDurableServiceWithPreparation` adds an individually addressed preparation RPC
and explicit `preparation-state` control. Native Unix startup selects the fixed
`netbird-preparation` sibling of `netbird-journal` beneath the validated individual
identity directory. Shared enrollment and Windows do not enable this staging
owner. Linux still requires the separate individual enrollment implementation;
package preparation is not evidence of independent Linux publisher trust.

The strict request binds the current certificate/device/scope, exact descriptor,
reviewed revision, live journal revision, UUID and deadline. The handler requires
the active broker binding and service certificate lifetime. It retains one private
artifact, holds the common executor mutex during preparation and rechecks a ready,
unchanged journal after native inspection. Controls remain available during the
download; a withdrawal or other journal change invalidates the result. No journal
execution attempt is created by preparation itself. Native installation requires
a separate matching command and journal admission.

Exact request replay rechecks the retained file without another download. A
changed source, approval, revision or deadline under that UUID conflicts; another
request cannot evict a live preparation. Readiness and responses expose no package
URL or local path. Replacement broker connections keep the same owner and cache;
stale callbacks cannot start work. Service cancellation reaches the stage, joins
its work and removes late artifacts before journal ownership is released.

A joined maintenance worker cleans expired or invalidated preparation within one
second when no inspection is active, and clears it on service cancellation. A
cleanup error poisons preparation readiness. Startup `ResetRoot`, called under
the exclusive installation journal lease, removes at most one abandoned stage
with an exact UUID directory and fixed package filename. It checks private
ownership and original file identity, bounds directory enumeration and refuses
unknown entries or symlinks. It never recursively removes a directory, repairs
permissions or touches the execution journal. Abandoned files carry no reusable
preparation authority after restart.
After a live stage fails, the owner only checks that its root is empty. Remaining
files stop preparation and are preserved; failed cleanup cannot invoke startup
recovery to delete a replacement path.

Owned broker fixtures cover exact replay, private correlation, changed authority,
connection replacement, command exclusion, journal changes during download,
expiration, cleanup failure and shutdown joining. Filesystem fixtures cover
partial downloads, bounded crash cleanup, extra files/directories, symlinks and
unprotected ancestors. The real native binding also receives the preparation RPC
and rejects an incompatible native target before HTTP access. No real NetBird
installer, daemon or provider is run by these tests.

The [console preparation component](https://github.com/the-luap/openuem-console/blob/5be886d170478dd199cee99bb69644e96394ebf6/docs/netbird-console-preparation.md) now has a separate durable admission
method and direct publisher. It checks both native capabilities and current approval/recipient
identity, commits the exact request digest before RPC, and retains correlated
results without another delivery on replay. [Native command admission](https://github.com/the-luap/openuem-console/blob/3597328d39f43894b2ad556246ad29532a6345d6/docs/netbird-installation-delivery.md) now rechecks
current authority and cancellation, reconstructs the exact live preparation and
commits its own attempt before one fresh installation command. Native attempts
exclude cancellation. Completed receipts can be recovered through read-only
queries under a renewed current identity without redelivery.
[Reviewed withdrawal and release](https://github.com/the-luap/openuem-console/blob/ab17d569a9a3ea56823b16274503ec0827b6eefc/docs/netbird-installation-resolutions.md) now use expiring reviews and an owned permanent resolution UUID; lost replies
reconcile without resending the installer. [Automatic dispatch](https://github.com/the-luap/openuem-console/blob/dc77e7b878432e99296b6b5a7ca8c5ff1fffde4e/docs/netbird-installation-dispatch.md) now continues retained prepared work with fresh admission and excludes uncertain
attempts from redelivery. Device lifecycle UI remains open.
Preparation alone remains cancellable and cannot authorize installation. The native macOS installer now
consumes the exact owned package under atomic current journal admission and
verifies its resulting state; a preparation response alone cannot authorize it.

The current shared contract pin is
`v0.11.1-0.20260914044144-fbef45520563`. Its complete race suite passes and the
preparation decoder fuzz run completes 11,748,164 inputs in 31.401 seconds. Final
macOS command/preparation/journal race suites pass in 5.638/4.201/7.633 seconds;
native agent binding regressions pass in 2.574 seconds. Linux journal/command/
preparation race suites pass in 5.208/3.793/3.820 seconds. All six complete builds
pass: Linux console, Linux/macOS/Windows agent and Linux/Windows worker, using
the same published shared revision rather than a local module replacement.
