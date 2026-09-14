# Native Linux package signatures

`internal/packagesignature.Verify` verifies staged DEB and RPM installers through
the system package-signature tools. A signature authorizes a publisher, not an
OpenUEM release. Callers must separately verify the signed release manifest,
platform, architecture, checkpoint and exact package hash before and after this
check. [Linux running-executable trust](linux-running-executable.md) now has its
own native provider. Protected [Linux package staging](linux-package-staging.md)
now joins publisher checks to signed-release HTTPS downloads and retained directory
ownership. Native installation, enrollment CLI and service activation remain
separate integration work.

## Protected prerequisites

Verification requires root. The staged candidate is a single-link 0600 regular
file of 1–512 MiB inside a 0700 directory. Its complete ancestry must already be
root-owned, with no group/other write access or special permission bits. Symlinks,
hardlinks, FIFOs, shared sticky directories and unsafe ancestors fail. Verification
never repairs permissions or provisions trust from downloaded package contents.

The native tools must be root-owned, single-link ELF files with protected ancestry
and owner execute permission. The verifier retains all ancestor and file handles,
checks inode/metadata and SHA-256 content before and after the native operation,
and passes the retained tool and candidate as file descriptors. Replacement of a
path, publisher key, policy, directory or equivalent-metadata content invalidates
the operation. Publisher directories have bounded, exact inventories; extra files
cannot silently add another native policy or keyring.

Root and the distribution's native tools/libraries remain inside this trust
boundary. These checks do not protect against a malicious root administrator.

## Independently provisioned publishers

Trusted material resides below `/etc/openuem/package-signing`. Provision it through
an independently authenticated administrative channel. Files may be publicly
readable, but all owners and ancestors must be root and no group/other write access
or special permission bits are allowed. A missing trust tree rejects verification;
the agent does not import keys or consult a package-supplied publisher URL.

RPM uses `/etc/openuem/package-signing/rpm/publisher.key`, a nonempty armored
OpenPGP public key file of at most 64 KiB. This is the only entry permitted in that
directory. The verifier invokes `/usr/bin/rpmkeys` with an explicit filesystem
keyring, empty RPM configuration/macro files, verification flags zero, and mandatory
signature **and** digest checking. The system RPM database and ambient user macros
provide no authority. Exit success must also report the complete native
`digests signatures OK` result; digest-only acceptance on older RPM is insufficient.
The owned fixture verifies this contract with RPM 4.18. Incompatible native output
or configuration semantics fail closed. Native signature coverage can exclude RPM
signature-header padding, which is another reason to retain the exact release hash.

DEB uses `/usr/bin/debsig-verify` and the protected system `/usr/bin/gpg` and
`/usr/bin/gpgv`. Its trust tree contains exactly `policies` and `keyrings`, with
matching directories for one to eight authorized full, uppercase 40-hex-digit
OpenPGP fingerprints. Short key IDs and fingerprint aliases are rejected.

Each `keyrings/<FINGERPRINT>` directory contains only `publisher.gpg`, an exported
binary public keyring of at most 64 KiB. Each `policies/<FINGERPRINT>` directory
contains only `openuem.pol`, with exactly the following UTF-8 bytes and a final
newline; replace all three placeholders with that full fingerprint:

```xml
<?xml version="1.0"?>
<!DOCTYPE Policy SYSTEM "https://www.debian.org/debsig/1.0/policy.dtd">
<Policy xmlns="https://www.debian.org/debsig/1.0/">
  <Origin Name="OpenUEM" id="<FINGERPRINT>" Description="OpenUEM package publisher"/>
  <Selection><Required Type="origin" File="publisher.gpg" id="<FINGERPRINT>"/></Selection>
  <Verification><Required Type="origin" File="publisher.gpg" id="<FINGERPRINT>"/></Verification>
</Policy>
```

Both selection and cryptographic verification require the exact origin signer.
Selection alone only checks signature presence. Optional rules, omitted signer
IDs, extra policies, external keyring paths and XML variations are rejected before
invoking the native tool. The verifier supplies explicit policy/keyring directories
and the exact policy filename; it never lists policies as a substitute for checking
the package. The native fixture uses debsig-verify 0.28 and SHA-256 signatures.

Publisher withdrawal and replacement are administrative trust changes. The agent
does not fetch online revocation information, import keys, or infer authorization
from an OpenPGP identity string. Removing a required key causes subsequent checks
to fail; changing trust during an active verification invalidates that operation.

## Native lifetime and owned evidence

The environment fixes PATH and locale and excludes ambient HOME, GNUPGHOME and RPM
configuration. Native verification runs without a shell, installation, package
scripts or executable payloads. The system DEB verifier uses its private temporary
working files; the isolated tests supply a dedicated temporary filesystem for them.

The public operation has a two-minute deadline. Diagnostics are bounded to 16 KiB
and never leave generic errors. Cancellation kills the owned process group and
joins the native leader. `waitid(WNOWAIT)` preserves the leader's PID until group
cleanup, including early leader exit with surviving descendants; only then does
the Go process wait reap it. This avoids signalling a recycled PID after reaping.

`scripts/check-linux-package-signatures.sh` creates a read-only, network-isolated
container with owned temporary trust and staging files. It generates two synthetic
RSA publishers and inert DEB/RPM packages. Only one publisher is provisioned; private
keys are removed before the Go race suite. No package is installed and no host
keyring, service or trust configuration changes. Required native tests must report
passes explicitly, so a skipped fixture cannot satisfy CI.

Tests exercise authorized signatures, foreign signers, unsigned packages, modified
payloads, ambient configuration, changed bytes/inodes/permissions, replacement
ancestors, extra or missing trust, weakened DEB policies, unsafe candidate objects,
output bounds, cancellation and descendants surviving their verifier's early exit.
These synthetic results do not establish acceptance of a production signed OpenUEM
release on a physical endpoint.

The complete isolated Linux race suite passes in 5.765 seconds, including all six
required native test families. macOS signature/staging regression races pass in
3.654/1.787 seconds; complete Linux and Windows agent builds pass, and Windows
signature tests cross-compile. Published native CI provides separate evidence.

Primary references: [Debian verification options](https://manpages.debian.org/testing/debsig-verify/debsig-verify.1.en.html),
[Debian policy semantics](https://sources.debian.org/src/debsig-verify/0.33/doc/policy-syntax.txt/),
[RPM filesystem keyring and mandatory verification source](https://github.com/rpm-software-management/rpm/blob/rpm-4.18.0-release/lib/rpmts.c),
[RPM signature and payload verification](https://github.com/rpm-software-management/rpm/blob/rpm-4.18.0-release/lib/rpmvs.c),
and [Linux wait semantics](https://man7.org/linux/man-pages/man2/waitpid.2.html).
