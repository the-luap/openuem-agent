# Native NetBird package ownership evidence

The native removal foundation now includes a private, read-only filesystem
inspector for the official macOS package. It is not configured as a removal-state
service and does not produce a wire removal descriptor. Launchd runtime ownership,
exact process identity, the removal owner and verified absence remain required
before enabling deinstallation.

## Inspected package state

The production entry point requires a root Darwin agent with native ACL support.
Paths and native utility arguments are fixed in code. No package URL, approval,
caller path, shell, installer script or NetBird executable supplies this evidence.
The observer checks:

- The protected root-volume package receipt and BOM, exact `io.netbird.client`
  receipt/version, positive installation time and complete `pkgutil --files` list.
- Every application file and directory, including the signed resource manifest.
  Additional or missing bundle objects, hard links, symlinks, nested mounts,
  unsafe ownership or write grants are rejected. Both executables must be thin
  Mach-O files for the current architecture, with executable permissions.
- Bundle identifier, executable, package type and both version fields from a
  bounded, unambiguous Info.plist. The same bounded plist parser preserves exact
  installation receipt checks and rejects duplicate keys in nested dictionaries.
- The optional fixed CLI symlink and system daemon plist. A present daemon must
  have the exact label, fixed NetBird program, `service run` prefix and supported
  typed settings. Alternate executables, chroots, users and unknown launchd keys
  are rejected. Optional missing objects remain part of the private fingerprint.
- Apple Developer ID code signatures for the complete bundle and the CLI, with
  strict verification across all architectures, exact signing identifiers and
  NetBird team `TA739QLA7A`. A signing identifier alone is insufficient. The fixed
  requirement contains Apple's Developer ID certificate constraints; local
  Gatekeeper exceptions cannot satisfy it.

The file walk is bounded by 1,056 objects, 16 levels and 256 MiB per pass, with
smaller plist and receipt budgets and a 20-second parent deadline. Every path
component is opened through an owned directory descriptor with `O_NOFOLLOW`.
First-pass handles remain open through verification, preventing immediate inode
reuse from impersonating the original object. Native read-only subprocesses have
clean environments, bounded discarded diagnostics and joined cancellation.

A second complete snapshot must match the first after receipt and signature
verification. The private fingerprint covers content hashes, object identity,
ownership, permissions, change metadata, native file flags, ACLs and exact link
targets. Read access times are excluded; shared ancestor directories bind identity
and permissions without binding unrelated directory contents. Raw service settings
and file paths are not exported. The evidence type refuses JSON and redacts normal
and Go-syntax formatting.

## Verification and remaining integration

Owned filesystem tests cover successful stable observations, private output,
receipt/list/bundle mismatches, missing and extra files, alternate links/services,
unsafe permissions, native ACL changes, failed signature/query utilities,
cancellation, resource bounds and mutation during verification. A Linux filesystem
counterexample exposed immediate inode reuse after unlink; retaining first-pass
handles fixes that case, and the portable owned suite passes after the change.
The Darwin race suites for installation, commands and journal also pass, as do
agent builds for Darwin, Linux and Windows and package test builds for Darwin
without CGO and Linux 386. Bounded native plist fuzzing is included in CI.

Read-only verification of the retained official 0.78.1 ARM64 package and extracted
bundle confirms the fixed NetBird team, bundle/CLI identifiers and code requirements.
The package, CLI, UI, installer and daemon were never executed. This artifact check
and owned process/filesystem tests do not constitute installed-device acceptance.

The private filesystem fingerprint deliberately cannot stand in for the shared
removal descriptor's complete state digest. The next native layer must join it
with actual launchd and process ownership, acquire the journal revision, recheck
each object before mutation, stop only the owned service/UI, remove the reviewed
objects and confirm absence. Configuration, logs, credentials and provider peers
remain outside local package removal. Partial or missing package receipts are
unavailable evidence, not proof of absence.

## Primary references

- [Apple code signing requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
- [Apple requirement language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [NetBird 0.78.1 service configuration](https://github.com/netbirdio/netbird/blob/v0.78.1/client/cmd/service.go)
- [Pinned native launchd implementation](https://github.com/kardianos/service/blob/becf2eb62b83/service_darwin.go)
- [Official macOS package installation](https://docs.netbird.io/get-started/install/macos)
