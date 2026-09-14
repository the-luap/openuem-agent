# Native macOS NetBird installation

Individually enrolled macOS agents running as root with CGO/native ACL support
can consume one privately prepared official PKG. They advertise the separate
`installation-state` capability only when the native preparation owner and
installer are configured. Other platforms, shared identities and macOS builds
without native ACL support cannot admit a new installation. Windows retains its
separate approved software workflow; Linux still needs individual enrollment and
independent package publisher verification.

The [console preparation method](https://github.com/the-luap/openuem-console/blob/5be886d170478dd199cee99bb69644e96394ebf6/docs/netbird-console-preparation.md) now provides durable
attempt/results, both capability checks and current approval/recipient authority.
It releases database locks before the bounded direct preparation RPC and never
redelivers an uncertain attempt. [Native console delivery](https://github.com/the-luap/openuem-console/blob/3597328d39f43894b2ad556246ad29532a6345d6/docs/netbird-installation-delivery.md) now rechecks current approval/revocation, actor authority
and recipient identity, reconstructs the complete live preparation and commits
one fresh version-three attempt before direct delivery. Native attempts exclude
cancellation; exact completed receipts or read-only receipt recovery open console
admission. [Reviewed uncertain-operation recovery](https://github.com/the-luap/openuem-console/blob/ab17d569a9a3ea56823b16274503ec0827b6eefc/docs/netbird-installation-resolutions.md) now retains expiring reviews, exact owned controls and release proofs.
Dispatch and lifecycle UI remain integration work. Its existing connection/registration publisher still rejects that
version. Local package removal remains unavailable.

## Admission and ownership

The command must match the live preparation's UUID, reviewed revision, exact
private descriptor and current individual certificate. It cannot have been issued
before that preparation, and both the preparation and certificate must remain
current through native preflight. The service holds the common executor mutex and
transfers exclusive preparation ownership into an installation lease.

Preflight validates the retained file, full source ancestry, native package
identity, complete payload evidence, notarization and protected target paths. It
performs no native installation. The journal's `BeginPrepared` compares the ready
revision under the same mutex that persists the attempt, closing the race with a
withdrawal or other journal change after inspection. A changed revision cannot
start the installer. Existing exact receipts remain readable without preparation.

After admission, preparation expiry cannot delete a file used by the installer.
The command's original deadline bounds execution and verification. Cleanup joins
the native process and releases the installation plan before deleting the owned
stage. Cleanup failure retains `unconfirmed`. Service shutdown cancels and joins
this complete sequence before releasing journal ownership. A duplicate request
reads the permanent result and never repeats installation. A crash without a
result retains the existing journal uncertainty and later-boot release rules.

## Native execution and resulting state

The only installer command is `/usr/sbin/installer -pkg <owned path> -target /`.
It runs directly as the existing root service, with a fixed system PATH, empty
inherited credentials/proxy environment, `/` working directory and null-device
streams. It has a ten-minute maximum or the command's earlier deadline. Unix
cancellation kills and joins the owned process group. This does not assert
rollback or termination of independent work delegated to Apple's `installd`.

The package must be nonrelocatable, target the root volume and request no restart.
All regular payload files must reside beneath `/Applications/NetBird.app`. The
streaming archive reader retains their complete SHA-256, size and executable
mode. It rejects unsafe ownership/modes before any installer runs. Source paths
require protected ancestry and a private, single-link file. Only fixed root-owned
macOS `/var`, `/tmp` and `/etc` aliases may redirect source traversal.

Target ancestors must be real protected directories. Root ownership and macOS
administrator-group maintenance are allowed; arbitrary user ownership, world
write access, symlinks and write-granting extended ACLs are rejected. Native ACLs
are checked through an opened, identity-validated descriptor. An absent extended
ACL is accepted only for that verified existing object. No path permissions or
ACLs are repaired.

The existing `/usr/local/bin/netbird` must be absent or the protected exact link
to `/Applications/NetBird.app/Contents/MacOS/netbird`. The vendor preinstall script
executes this path, so other distributions and redirected parent directories are
rejected before mutation. After installation the exact link is required, together
with every regular payload file's exact bytes and executable mode. This matches
the official PKG layout; the [vendor migration instructions](https://docs.netbird.io/get-started/install/macos)
require removing/unlinking an existing Homebrew installation before using PKG.

A zero installer exit is insufficient. The agent queries the fixed native receipt
with `/usr/sbin/pkgutil --volume / --pkg-info-plist io.netbird.client`. A bounded
strict plist parser requires the exact package identity/version, root volume,
root installation location and positive installation time. It rejects duplicate
keys, nested values, ambiguous fields and unexpected XML directives. It accepts
only Apple's exact standard plist DOCTYPE and never resolves external entities.
The retained package is rehashed after native execution as well.

`completed` confirms this receipt, payload and CLI-path evidence. It does not
prove that the NetBird daemon is connected, that its service started, or that a
provider enrollment succeeded. Those states use their separate observation and
registration workflows. Errors retain a neutral unconfirmed outcome without
publishing native diagnostics, package URLs, local paths or credentials.

## Validation

Owned fixtures cover exact preparation/command matching, certificate/deadline
changes, journal admission races, retained replay, cleanup failure and service
shutdown. Native filesystem tests cover full hashes, executable modes, missing
files, hard links, symlinked ancestors, foreign CLI links, writable directories
and macOS ACL grants. Owned inert subprocesses verify fixed arguments, clean
environment, discarded diagnostics and joined cancellation. No real NetBird
installer, daemon, maintainer script or provider is executed by these tests.

A read-only check of the official v0.78.1 ARM64 PKG verifies all ten regular
payload files. Its outer SHA-256 is
`220f9187aa92c22f20107b9291fd41ab0742e6a70ba8cd360286d6ddf35db585`.
The complete CLI and UI hashes are independently checked against
`aad83f2e496c8cb9a61c408c1aa184ff5cd2ebace7c554f539a0162c2335c9b8` and
`5311acbf30e887a4321f77362d9f1296020f426adedd113dcfb12f878bd55b1f`.
These read-only checks and inert tests do not replace physical installation,
upgrade, cancellation, reboot and removal acceptance on an authorized endpoint.

Final checks use published shared revision
`v0.11.1-0.20260914054338-0060dbf7d6a4`. macOS installation/command/journal race
suites pass in 6.962/7.205/7.605 seconds and the complete agent runtime suite in
23.429 seconds. Linux journal/command/installation races pass in
4.839/5.118/6.228 seconds. The native receipt fuzz run completes 1,479,183 inputs
in 31.475 seconds. The official PKG read-only check passes in 5.316 seconds.
macOS installation/command tests also pass with CGO disabled, preserving rejection
without native ACL support. All six complete builds pass for the Linux console,
Linux/macOS/Windows agent and Linux/Windows worker. The compiled console publisher
fixtures still reject installation through connection/registration admission.
The CI platform suites now include native preparation and the execution journal;
Linux CI also runs the bounded receipt fuzzer.
