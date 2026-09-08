# Individual endpoint identity storage

The `internal/enrollmentstore` package starts the protected endpoint-storage work
for individual Windows/Mac enrollment. Both native backends are implemented;
the durable enrollment state machine connects them to the bounded HTTPS client.
The [opt-in service runtime](individual-agent-runtime.md) now loads that identity
before legacy certificate configuration. The [native enrollment command](native-enrollment-command.md)
now connects explicit bootstrap authorization and verified installer/executable
bindings. Renewal, finished end-user installers and service activation remain
required integration steps.

## Durable enrollment and recovery

`Store.Enroll` requires an independently authorized `Bootstrap`: server HTTPS
origin, invitation, platform, architecture, device name and verified release
digest. Syntax checking does not establish release or server trust. These fields
bind subsequent retries; changing any of them returns `ErrConflict`
without a claim or silent replacement of the existing installation.

`Store.EnrollVerified` accepts the shared library's verified signed bootstrap
configuration and additionally persists its expected organization/site IDs and
release sequence. It rechecks the current durable checkpoint, config/release
validity, and expiry before and after the HTTPS claim. A response for another
organization/site is rejected before identity publication even if its certificate
otherwise matches the local key. Complete identity loads also verify that scope.
The caller still independently authorizes the origin and signing keys and verifies
the package's native signature before invoking the enrollment method.

`Store.Checkpoint` returns zero only for an actually empty installation. Pending
state already protects the selected sequence/digest, including after a lost reply.
The earlier explicitly configured claim API permits records without the newer
optional scope/sequence fields for compatibility. Such records remain loadable;
they cannot reset the signed bootstrap checkpoint to zero. Migrating that preview
state requires an explicit future operation rather than silent key replacement.

The first attempt generates an RSA certificate key and a user NKey locally, then
exclusively publishes a protected `pending` record before HTTP. Every caller,
including the winning writer, reloads that record before signing a request.
Competing writers discard their own generated keys and use the persisted winner.
The HTTPS client uses system roots or separately authorized server roots, rejects
redirects and sends only public CSR/key proofs. An issued identity authority is
never installed as HTTPS trust.

After validating the certificate's key, identity, purpose, lifetime and expected
WSS origin, the store exclusively publishes `identity`. That record contains the
public response and a SHA-256 binding to the exact pending record. It returns only
the reloaded, validated committed identity. A competing complete publication wins
without replacement. A lost HTTP response, failed local write or cancellation
retains pending keys for an explicit retry; an already completed enrollment makes
no new claim. The pending record remains protected after completion because it
holds the keys and deleting it could race another process recovering issuance.

`Store.Load` distinguishes empty (`ErrMissing`), pending (`ErrPending`) and ready
states. Orphaned, inaccessible, malformed, mismatched or expired state returns an
error, never an empty installation or a request to fall back to legacy credentials.
An expired/revoked invitation can leave pending state that requires an explicit
future recovery/re-enrollment workflow; this package does not delete or overwrite
it automatically. Certificate renewal is also a separate pending implementation.

The private, versioned, length-framed codec encodes bootstrap metadata, PKCS#8 RSA
bytes and a copied NKey seed only at the native storage boundary. It rejects
truncation, trailing data, oversized fields, weak/wrong key types and ambiguous
JSON. Each decoded identity owns independent keys and refuses JSON serialization.
Owned plaintext buffers and native outputs are cleared; Go's RSA internals can
retain private precomputation, so complete erasure of every managed-memory copy is
not guaranteed. `Store.Close` joins active operations; callers cancel active HTTP
contexts before shutdown and stop key users before `Identity.Close`.

## Windows storage boundary

`OpenNative` receives an absolute directory beneath an installer-controlled parent.
It creates one directory if needed, with Administrators ownership and a protected,
inheritable DACL granting access only to Local System and Administrators. It does
not create parent directories or repair existing shared/user-owned directories.
Every operation rechecks the directory and every read checks the opened file's
owner and ACL. The parent must prevent untrusted users from renaming the directory.
Use a protected installation/data parent, not a user-controlled working directory.

Records are owned by Administrators and have a protected DACL for Local System
and Administrators only. There is no additional allow entry for the installer's
individual user SID. This permits an elevated installer and the Local System
service to use the same state, while rejecting ordinary-user access. Privileged
administrators remain inside the trust boundary.

The backend encrypts opaque record bytes with Windows DPAPI using
`CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN`. It does not request UI.
Machine protection is necessary for the installer/service account transition;
it does not by itself provide a file-access boundary. Microsoft documents that
any local user who obtains a machine-protected blob can decrypt it. Therefore the
backend rejects shared ciphertext files **before decryption**.
[CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata),
[CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata).

The public, domain-separated optional entropy binds `pending` and `identity`
records to distinct purposes. It is not a second secret. Copying one stage's blob
to the other filename does not make it a valid record of the other type. DPAPI
authenticates record integrity. The backend limits plaintext to 128 KiB and
protected data to 192 KiB, clears native output buffers before `LocalFree`, and
returns generic errors without keys, record content, paths or operating-system
diagnostics. A caller owns each returned plaintext buffer and must clear it.

`Create` writes an already encrypted temporary file with its private DACL in place
before the first byte. It flushes and closes that file, then publishes it with
`MoveFileEx(..., MOVEFILE_WRITE_THROUGH)` without `REPLACE_EXISTING`. Competing
processes get one complete winner; they must load that record instead of replacing
it. Failed attempts clean up their own temporary file. The backend never silently
replaces existing state, and corrupted or inaccessible records never trigger a
plaintext fallback. `Store` adds the enrollment/recovery state machine on top of
these two immutable storage primitives.

Legacy configuration remains the default when the individual service mode is not
configured. The explicit native `enroll` command prepares protected credentials;
the finished end-user installer and automatic activation are still outstanding.

## macOS storage boundary

The root launchd daemon uses only `/Library/Keychains/System.keychain`, following
[Apple TN3137](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains).
An absolute, private installation directory determines a SHA-256 service namespace.
Generic-password items use that service and the record name as their account.
Queries explicitly restrict the search list to the opened keychain; they never
fall back to a user's login keychain. All native operations disable interaction.
A locked, inaccessible or corrupt keychain fails closed without a password prompt.

Each immutable item has an explicit trusted-application ACL for the executable
creating it. The installer must invoke the installed agent to perform enrollment,
so the service uses the same application identity. Production release signing and
upgrade compatibility must be verified with the actual signing credentials.
The bridge uses the legacy file-keychain APIs required by system daemons, with
deprecation suppression limited to that C bridge. Builds without CGO report an
unsupported backend and cannot silently fall back to plaintext files.

`SecItemAdd` exclusively publishes a complete record. Independent handles cannot
replace each other's keys. Reads copy at most 128 KiB into caller-owned memory;
temporary native copies are cleared before freeing. Handles serialize operations
and close against their Core Foundation reference.

## Verification

The native Windows workflow runs:

```sh
go test -count=1 ./internal/enrollmentstore ./internal/agent
```

Tests cover encrypted bytes on disk, restart, immutable publication, twelve
concurrent publishers, ciphertext tampering, purpose confusion, bounded records,
shared file/directory rejection and preservation of existing access controls.
The service-account test creates one uniquely named, temporary Windows service
running the test executable as Local System. That process decrypts the fixture
written by the elevated test process and publishes another protected record,
which the parent reads. The test stops/deletes only its own service and cleans up
its private temporary directory. Native execution requires an elevated Windows
runner with Service Control Manager access; a cross-build alone does not verify it.

The native macOS workflow runs:

```sh
CGO_ENABLED=1 go test -race -count=1 -tags openuem_keychain_test ./internal/enrollmentstore ./internal/agent
```

The explicit test tag enables a fixture bridge excluded from production builds.
Tests create password-protected temporary keychains, restrict all queries to
their own items and delete only their own keychain references. They verify locked
keychain rejection, namespace separation, eight competing publishers, encrypted
disk contents, the 128 KiB boundary and recovery/publication by a separate process
of the same executable. They do not enroll the workstation or read existing user
credentials. Signed agent/installer integration and physical Windows/Mac
acceptance remain separate requirements.

All three CI platforms run the common state-machine tests and build the complete
agent. Windows and macOS also run the lost-response HTTPS/HTTP2 recovery scenario
using their actual DPAPI/keychain backend. The isolated issuer verifies that
durable keys exist before the first request, commits issuance, interrupts its
first response and accepts only the same key binding on retry. Other tests cover
concurrent enrollment, both possible outcomes of a failed publication, changed
bootstrap values, wrong returned scope, release rollback, corrupt/orphaned records,
cancellation and shutdown. A timed HTTPS test verifies that a configuration
expiring after server issuance cannot publish a ready identity. These fixture
tests complement the console's real PostgreSQL/gateway
claim tests; they do not claim a physical installed-agent acceptance result.
