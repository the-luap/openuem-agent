# Native Linux credential encryption component

The private `linuxCredentialCipher` provides bounded authenticated encryption for
the [durable Linux identity backend](linux-identity-storage.md), now connected to
`OpenNative`. The installed Linux enrollment command, native package trust and
individual-service activation remain separate integration requirements.

## Native protection and scope

The provider requires root, `/usr/bin/systemd-creds` and an already provisioned
`/var/lib/systemd/credential.secret`. It does not generate or replace the OS key.
The trusted installer must provision that prerequisite separately. Supported
native host-key records use systemd's AES-256-GCM host format. The OS key is bound
to the installation's machine ID and protected by root-only filesystem access.
This is host-key protection, without TPM sealing; possession of the host key
permits decryption. [systemd credential documentation](https://github.com/systemd/systemd/blob/v252/man/systemd-creds.xml),
[host-key implementation](https://github.com/systemd/systemd/blob/v252/src/shared/creds-util.c).

Every native program/key ancestor is opened without following symlinks and must
be root-owned, without group/other write access or special mode bits. The program
must be a regular executable ELF file, bounded to 32 MiB, with exactly one link.
The existing host key must be a root-owned, single-link 0400 regular file with the
supported 4,112-byte representation. All objects and their ancestors remain open.

Before and after each native call, validation checks the complete namespace,
file ownership, mode, size, identity, modification/change times and SHA-256
content fingerprints. Hash reads are bounded and their temporary buffers are
cleared. Time metadata alone is insufficient: immediate in-place rewrites can
retain equivalent timestamps. The native process executes through the retained
program descriptor. An OS upgrade or key replacement requires opening a fresh
provider; an existing provider never silently adopts it.

The credential name hashes a versioned domain, canonical credential directory
and valid immutable record name. Encryption also embeds that exact context in the
protected plaintext envelope. A caller cannot reuse a pending credential as an
identity or move it into another installation namespace. The envelope is required
even when the native blob omits its own credential name.

The encoder explicitly requests `--with-key=host`. The decoder first requires the
[systemd host-format identifier](https://github.com/systemd/systemd/blob/v252/src/shared/creds-util.h),
strict bounded base64 and a complete minimum header. Null-key, TPM-only, unknown
and malformed formats fail before native decryption. Header recognition grants
no authenticity: systemd must successfully authenticate/decrypt the complete
blob and the returned context envelope must match. Wrapped native base64 is
normalized before persistence; other whitespace and ambiguous encodings fail.

## Lifetime and data handling

Only fixed native commands, a hashed purpose name and standard-input/output paths
appear in process arguments. A minimal environment excludes ambient loader,
credential-path and user configuration overrides. Plaintext passes through pipes
and bounded owned buffers; the provider writes no plaintext file and discards
native diagnostics. Input is limited to 128 KiB and native output to 192 KiB.
Returned plaintext belongs to the caller and must be cleared after decoding.

Calls serialize against one provider and have a ten-second ceiling. Parent
cancellation and provider close stop the owned process group; pipe waiting has
an additional one-second bound. Close joins the active operation before releasing
all retained descriptors. Failed, cancelled or mismatched native results return
only a generic unavailable error. They do not fall back to another encryption
mode or return partial plaintext.

## Owned verification

`scripts/check-linux-credential-encryption.sh` builds a minimal Go 1.26.8 / Debian
Bookworm fixture with the distribution's systemd package. Its run has no network,
a read-only root/source/module cache, an explicit synthetic machine ID and a
private temporary filesystem for the generated host key. Native tests refuse to
run unless that exact fixture identity and temporary key filesystem are present.
The script removes its exact owned container, temporary image tag and host-side
fixture files, including after interruption.

The full enrollment-store race suite includes native encryption/decryption at the
one-byte and 128 KiB bounds, changed record and installation contexts, tampering,
nameless/foreign envelopes, actual null-key credentials, unsafe keys/ancestors,
replacement and in-place rewrites with equivalent metadata, ambient environment
overrides, cancellation, concurrent close and unbounded native output. Existing
Linux process-ownership and common enrollment-state tests run in the same fixture.
No workstation key, host service or real endpoint enrollment is used.

The dedicated `linux-credential-encryption` CI job runs this owned fixture after
caching dependencies. It now also exercises the complete durable Linux backend;
native package trust and service activation remain separate from these results.

The complete owned Linux enrollment-store race run passed in 73.904 seconds.
The native fixture used systemd 252.39 on Linux ARM64; CI exercises Linux AMD64.
