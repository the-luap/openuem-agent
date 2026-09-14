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

This is an implementation component, not a completed installer feature. Console
approval/storage, authenticated installer command/capability, durable attempts,
install/remove processes, exact resulting state and
uncertainty recovery remain required before enabling installation or local
uninstallation. Read-only checks of exact official v0.78.1 artifacts now pass;
physical/native installation acceptance remains separate from those checks.
