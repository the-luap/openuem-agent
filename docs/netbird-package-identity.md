# NetBird native package identity

`Stage` now requires native identity preflight before returning a prepared Unix
package. `Prepared.Inspect` can repeat it against the original descriptor. The
entire approval/source/target digest, protected directory, file identity, length
and SHA-256 are checked before and after inspection. Inspection and cleanup hold
the same mutex; inspection never grants execution authority or reports an
installation result.

## Linux

Fixed read-only `/usr/bin/dpkg-deb --show` and `/usr/bin/rpm --query --package`
queries return only selected metadata fields. The DEB name, version and native
architecture must match exactly. RPM compares name, epoch/version/release and
architecture; zero epoch is omitted from the approved version, while a nonzero
epoch is retained. For example, the v0.78.1 artifacts contain DEB version
`0.78.1` and RPM version `0.78.1-1`. No semantic-version or filename inference
substitutes for these values.

The architecture mappings are `amd64`/`arm64`/`i386` for DEB and
`x86_64`/`aarch64`/`i386` for RPM. RPM uses empty rc/macro configuration, an inert
database path and disabled plugins/manifests. Query output is not publisher trust:
an unknown signing key may still permit metadata queries. No signature/digest
verification bypass flag or global trust change is added.

Each utility runs as the service identity with a fixed environment, its own
process group, a one-minute deadline and a shared 16 KiB stdout/stderr limit.
Cancellation, parser errors, nonzero exit and overflow reject the result; every
started child is waited for. Diagnostics are discarded and cannot expose package
source coordinates or inherited credentials. The implementation follows the
[Debian query interface](https://manpages.debian.org/bookworm/dpkg/dpkg-deb.1.en.html)
and [RPM query/configuration options](https://rpm.org/docs/4.20.x/man/rpm.8).

## macOS

The existing native notarization assessment remains mandatory. A bounded XAR
reader then uses the retained file descriptor, without extracting files or
evaluating Installer code. It matches `Distribution` product/references and the
referenced component's `PackageInfo` to `io.netbird.client` and the exact version.
External package references, scripts in the distribution, conflicting metadata,
duplicate entries and invalid archive offsets are rejected.

The official ARM64 v0.78.1 distribution advertises both `x86_64` and `arm64`, so
that field alone cannot prove the selected package architecture. Preflight also
streams the component's gzip/odc CPIO payload and checks the thin Mach-O executable
headers of both `NetBird.app/Contents/MacOS/netbird` and `netbird-ui`. Each must
occur once, be an executable regular file without hard links, and match the
approved architecture. Path traversal, linked entries, case aliases, non-ASCII
paths, missing binaries, corrupt gzip streams and trailing archives are rejected.

The supported profile is the vendor's separate architecture PKG: a version-one
XAR, zlib or raw members, gzip/odc payload and thin ARM64 or x86_64 executables.
Universal binaries and other encodings require a future explicit profile rather
than a filename fallback. Limits include a 128 KiB TOC, 32 KiB metadata documents,
128 XAR entries, 1,024 CPIO entries, 256 MiB decompressed payload and a one-minute
inspection deadline. XML depth and token counts are bounded. Native trust plus
the approved full-package digest authenticate bytes; the parser is not a second
signature implementation.

The signed v0.78.1 archive repeats identical `name` elements for several members.
Those identical values are accepted once; conflicting values are rejected.
This also avoids the duplicated paths produced by the host's libarchive reader.
Embedded XMLDSIG certificate elements remain separately qualified and cannot
alias package metadata.

## Evidence and integration boundary

Read-only checks use these exact [official v0.78.1 release assets](https://github.com/netbirdio/netbird/releases/tag/v0.78.1),
with byte lengths and SHA-256 verified against release metadata:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `netbird_0.78.1_darwin_arm64.pkg` | 22699908 | `220f9187aa92c22f20107b9291fd41ab0742e6a70ba8cd360286d6ddf35db585` |
| `netbird_0.78.1_linux_arm64.deb` | 14380360 | `ae3a9e2c3207c78431a2003a6677a4ad5f71a86b139ff17fa32484fbc5022f3c` |
| `netbird_0.78.1_linux_arm64.rpm` | 14307484 | `202a1c36f8300a8a3b3603fa2b9c316cefd582afb2c6f6020e49577256d84c3d` |

All three pass their native metadata checks and reject an AMD64 descriptor for
the ARM64 artifact. Apple's read-only assessment also returns
`source=Notarized Developer ID` for the PKG. No NetBird executable or installer is
run. Linux reads run in an owned container without network access. The optional
test uses `NETBIRD_PACKAGE_EVIDENCE` and verifies these immutable hashes before
and after reading; normal CI uses generated inert archives and helper processes.

Adversarial fixtures cover metadata ambiguity, architecture mismatches, invalid
archives and bounds, process cancellation/reaping, clean environments, output
overflow, changed bytes and concurrent cleanup. Seeded fuzz targets cover XML,
CPIO payload and XAR parsing. macOS/Linux race suites and all three agent platform
builds pass, including existing NetBird command, journal and service regressions.

Console approval storage, authenticated installer capability/command delivery,
durable execution admission, native install/remove, resulting-state observation
and uncertainty recovery remain open. Linux publisher provenance and physical
installation acceptance require their own evidence. Existing installer
subscriptions continue to reject requests.
