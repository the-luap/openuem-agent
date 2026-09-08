# Individual endpoint identity storage

The `internal/enrollmentstore` package starts the protected endpoint-storage work
for individual Windows/Mac enrollment. It is currently a Windows backend, not an
enabled replacement for the legacy agent runtime. The enrollment record format,
pending-key/recovery state machine, native bootstrap command, runtime selection
and macOS keychain backend remain integration steps.

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
plaintext fallback. Its two immutable records are only a storage primitive;
callers still need the enrollment/recovery state machine before sending a claim.

Existing legacy configuration and shared certificate behavior are unchanged by
this unconnected package. No end-user activation flag is introduced yet.

## Verification

The native Windows workflow runs:

```sh
go test -count=1 ./internal/enrollmentstore
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

The macOS backend must use a file-based keychain for a system daemon, following
[Apple TN3137](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains).
Tests must use an isolated temporary keychain; they must not enroll this workstation
or read existing user credentials. Signed agent/installer integration and physical
Windows/Mac acceptance remain separate requirements.
