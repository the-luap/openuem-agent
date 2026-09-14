# Native Linux identity storage

Linux `enrollmentstore.OpenNative` now implements the durable encrypted record
backend. It uses the [native systemd credential provider](linux-credential-encryption.md)
and preserves the common enrollment, recipient, rotation, software and renewal
state-machine contracts. The shared Linux release/bootstrap protocol is now
connected to protected enrollment and renewal on AMD64/ARM64. Native DEB/RPM
[publisher verification](linux-package-signatures.md) is available separately.
The [running-executable provider](linux-running-executable.md) now binds the actual
kernel image to signed release bytes. Package staging, the installed enrollment
command and individual-service activation remain separate integration work.

## Installation and encryption boundary

The caller must be root and supply a canonical absolute installation path beneath
existing trusted ancestors. Every ancestor is root-owned, without group/other
write access or special mode bits; symlinks and shared sticky directories fail.
The backend creates only the final 0700 installation directory and its private
`credentials-v1` child. Existing directories must already satisfy that policy.
It never creates missing ancestors or repairs ownership and permissions.

The preprovisioned systemd host key and native executable are validated before
any state directory is created. There is no automatic key setup or plaintext
fallback. Encryption binds each record to its canonical credential directory and
record name. Copies into another installation or another record slot fail native
authentication or context validation. Root and possession of the host key remain
inside the trust boundary; the format does not provide TPM sealing.

All directory ancestors remain open and every operation revalidates their exact
namespace, ownership and mode. Native program/key replacement invalidates an
existing backend. A fresh backend must explicitly reopen current prerequisites.

## Immutable publication and reads

Committed files use a valid record name followed by `.cred`. Each is a root-owned,
single-link 0600 regular file, containing at most 192 KiB of ciphertext for a
1–128 KiB plaintext record. Reads are bounded and nonblocking, refuse symlinks and
unsafe metadata, and return data only after authenticated decryption and a second
namespace, inode, metadata and SHA-256 content check. Equivalent timestamps cannot
hide changed ciphertext. Failed reads return no plaintext.

Creation encrypts first, writes a uniquely named private temporary file, flushes
it and rechecks its exact bytes and inode. Linux `renameat2(RENAME_NOREPLACE)` then
publishes exclusively, followed by a directory flush and publication validation.
There is no overwrite or weaker publication fallback. Independent handles and
processes may compete: one writer publishes and the others reload its complete
record. Storage does not acquire the separate service lease.

A failure before publication removes only that writer's still-matching temporary
inode. A failure after publication preserves the committed record, including an
uncertain directory flush; an explicit retry must load it. Existing crash fragments
are never removed. Canonical `.enrollment-<UUID>.tmp` files with private bounded
metadata are recognized as unpublished fragments. Their names carry no authority
to resume a claim: the common state machine sends HTTP only after publishing and
reloading the committed pending record.

Close cancels native encryption/decryption, joins active operations and releases
every retained descriptor. It does not remove records or release another owner's
service lease.

## Restoration and runtime evidence

The credential child admits only canonical known record names and private crash
temporaries. Unknown entries, malformed names and unsafe objects prevent opening,
creation and interpretation of missing records as empty state. Inventory is bounded
to 20,000 entries and covers every valid security-record family, including the
last software, rotation and renewal slots, without probing thousands of absent files.

The installation parent may also contain the service lease and runtime directories
such as `netbird-journal` and `netbird-preparation`. These coexist with a complete
identity. If identity records are missing, any surviving runtime object prevents
new enrollment, even when the credential child has been restored empty. Only the
exact empty private service lock is excluded from that evidence. A partial restore
cannot silently create new keys or reset a release checkpoint.

## Owned verification

`scripts/check-linux-credential-encryption.sh` runs the complete enrollment-store
race suite in an isolated Linux container using the actual systemd provider,
an explicit synthetic machine ID and a temporary host key. No host identity,
enrollment, key provisioning or service activation is involved.

Native tests cover lost HTTP replies and restart recovery; all common durable
state-machine families; maximum records; twelve competing handles; a separate
process; copied and tampered ciphertext; unknown and unsafe namespaces; surviving
crash fragments; partial restoration; runtime and service-lease coexistence;
changed ancestors; equivalent-metadata rewrites; and concurrent close. Additional
fixtures reject unprivileged creation and missing prerequisites without creating
state, preserve unsafe initial directories, and force a partial write with a child
process file-size limit before a successful explicit retry.

The final complete Linux race suite passed in 116.771 seconds, including the
prerequisite and partial-write fixtures. The macOS enrollment-store race suite
passed in 63.807 seconds and the full Linux agent build passes; the Windows storage
test binary cross-compiles. Native Windows execution remains separate evidence.
After integrating shared Linux protocol version `2dbc458eb28c`, the complete
native Linux store race suite passes in 135.166 seconds. macOS storage, installed
command, package staging and runtime-option regression suites also pass, as do
complete Linux and Windows agent builds. Linux package staging and installed-command
admission are still explicitly unavailable; native publisher verification now has
its own isolated tests and does not remove those installation gates.
The original cross-platform workflow fixtures retain their Windows/Mac metadata.
Additional native fixtures now use actual Linux platform/architecture metadata,
independently signed configuration and the bounded HTTP/2 client. They lose an
issuance reply, recover the same protected keys, preserve the release checkpoint,
lose renewal preparation/confirmation replies and recover the exact committed
handoff. Reopening native storage retains the resulting Linux identity and scope.
Their package bytes remain synthetic; these results do not establish native
package-signature trust or authorize service installation.
