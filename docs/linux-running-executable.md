# Linux running executable identity

`bootstrapinstall.OpenRunningAgent` now has a native root-only Linux provider.
Before any enrollment network request it retains the kernel-selected
`/proc/self/exe` image and separately opens the canonical installed path through
root-owned, non-writable directory ancestors. Every path component is opened
without following symlinks. The kernel image and canonical file must have the
same device, inode and protected metadata; byte-identical copies cannot substitute
for the running process image.

The file must be a single-link regular executable of 64 bytes to 512 MiB, owned by
root, with no group/other write access or special permission bits. The provider
requires a native 64-bit little-endian AMD64/ARM64 ELF executable or PIE header.
The check validates native format and file identity; it is not remote attestation
of process memory, libraries or the operating system. Root remains trusted.

All ancestors, the canonical file and kernel image remain open for the lifetime
of `Executable`. Path lookup, signed release verification and protected stored
binding verification recheck this namespace and the original metadata/content.
SHA-256 detects equivalent-metadata rewrites as well as ordinary changes. A
replaced ancestor, copied path, changed mode, hardlink, removed executable or
changed file loses authority. Close releases the kernel, file and ancestor handles
under the existing executable mutex and is idempotent.

Public Linux `Executable.Verify` requires this native witness, the exact running
platform/architecture, the protected checkpoint and independently signed
`agent_size`/`agent_sha256` metadata. Generic file opening cannot authorize a Linux
running image. A package checksum or version label never substitutes for the
separate executable binding. After completed enrollment, `VerifyStoredBinding`
continues to require the protected identity's exact size/hash and retained native
image, even when the invitation or release envelope is no longer current.

This component does not remove the separate Linux package-staging, installed
enrollment-command or service-activation gates. Native DEB/RPM
[publisher verification](linux-package-signatures.md) is available separately;
production releases still need signing, installation and physical acceptance.

`scripts/check-linux-executable.sh` runs all bootstrap-installation race tests in
a read-only, network-isolated Linux container with a private executable tmpfs.
It reads the actual Go test binary as fixture data, binds it in independently
signed Linux release/configuration envelopes for both package formats, and checks
the real kernel image. Additional copies are never executed. Tests reject a
different inode with identical bytes, unsafe owners/modes/ancestors, symlinks,
hardlinks, FIFOs, incompatible ELF headers and later namespace/content changes.
Required native families must explicitly pass; skipped native tests cannot satisfy
the CI job. No installed host agent, service or enrollment is touched.

The complete isolated Linux suite passes in 1.903 seconds. macOS bootstrap,
enrollment-command and activation-command race regressions pass in
1.613/1.902/4.504 seconds. Complete Linux and Windows agent builds pass, and the
Windows bootstrap test binary cross-compiles.
