# macOS service app bundle assembly

`openuem-macos-bundle` builds the app layout needed by the macOS 13+ Service
Management API. This is an offline release preparation step, not an installer or
service activation command. It copies an already built agent into a new bundle
and generates its app and daemon property lists. No device configuration, tokens,
keys, identity state or signing credentials enter the bundle.

Apple's [current helper migration guidance](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos)
places daemon property lists in the calling app's `Contents/Library/LaunchDaemons`
directory and uses a bundle-relative `BundleProgram`. Apple's
[package installer sample](https://developer.apple.com/documentation/ServiceManagement/updating-your-app-package-installer-to-use-the-new-service-management-api)
also supports a GUI-less registration app. Keeping these files inside the signed
bundle seals the service definition with the executable. New integration will use
`SMAppService`; its registration status describes authorization, not completed
agent initialization. LaunchDaemons require administrator approval before launch.
[Registration behavior](https://developer.apple.com/documentation/servicemanagement/smappservice/register())

## Build a draft

Run in a trusted macOS build workspace with trusted ancestor directories. The
output directory must already exist, be owned by the invoking user or root and
have no group/other permissions. The builder does not change an existing parent.
The input must be an owned, non-writable-by-others, single-architecture 64-bit
Mach-O executable with an entry-point load command. Universal, 32-bit, object,
library and non-Mach-O inputs are rejected. Build each supported architecture
separately so it matches the release artifact's target.

```sh
mkdir -m 700 /absolute/build/output
go run ./cmd/openuem-macos-bundle \
  -agent /absolute/build/openuem-agent \
  -output /absolute/build/output \
  -version 0.12.0 -build 42 -architecture arm64
```

`-version` accepts a canonical numeric `major.minor.patch` with up to four digits
per component; development prefixes/suffixes are excluded from the app's version.
`-build` is a canonical integer from 1 through 9999 for `CFBundleVersion`.
`-architecture` accepts `arm64` or `amd64`. These are requested packaging metadata;
the builder does not attest the source revision or embedded agent version. The
release pipeline must build the intended commit and reconcile its version.

The resulting file contents are deterministic for the same input and options:

```text
OpenUEM Agent.app/
  Contents/
    Info.plist
    MacOS/openuem-agent
    Library/LaunchDaemons/org.openuem.agent.daemon.plist
```

The app identifier is `org.openuem.agent`. The daemon uses the copied executable
with `serve -identity-directory /Library/OpenUEMAgent/identity`, root/wheel and
umask 077. It starts at load, retries abnormal exits with a 30-second throttle and
allows 30 seconds for shutdown. The operating system can terminate work beyond
that shutdown window; this does not prove that all agent OS operations honor
cancellation. Code directories/executable have mode 0755 and public metadata
0644. The build parent remains private. Final installation must establish root
ownership, trusted ancestors, operational INI/log directories and native identity
storage separately. The fixed identity location allows per-device state to remain
outside the sealed app rather than rewriting its plist after signing.

The input/output descriptors remain open through assembly. Source and copied
bytes are hashed and compared, and original file identity, permissions, size and
modification metadata are rechecked. New files use exclusive creation in an owned
staging tree; publication uses macOS's exclusive directory rename. Existing apps,
files or symlinks are never replaced. Competing builders preserve one winner and
remove only their own staging trees. The workspace and its ACLs must still be
trusted: these POSIX ownership/mode checks are not an audit of all ancestor ACLs,
mounts, source code or the build host.

Success writes public JSON with `published`, `path`, `version`, `build`,
`architecture` and `requires_release_signing: true`. No executable hash is exported
at this stage. Invalid input returns exit 2, cooperative cancellation 130 and
other failures 1. A synchronization error after rename retains the published
bundle and reports its public result with a nonzero exit. Raw filesystem errors
and invalid argument values are omitted. Abrupt process/OS termination can leave
an owned staging directory; crash recovery is not automatic.

## Signing order and remaining integration

1. Build the intended single-architecture agent and assemble its complete bundle.
2. Sign the final executable and app bundle using the release team's Developer ID,
   hardened runtime and appropriate timestamp. Do not modify sealed metadata after
   signing. An input may already carry a Go ad-hoc signature; assembly alone does
   not make it a release-approved app.
3. Compute the signed agent executable's final size and SHA-256 for the release
   manifest's `agent_size`/`agent_sha256`. Signing can change these bytes.
4. Package that unchanged signed app, sign the installer with Developer ID
   Installer, notarize and staple through the authorized release pipeline. Verify
   the resulting app/installer with native policy before distribution.
5. Hash the final distributed installer separately and sign the release manifest
   with the independent release key. The installer and agent hashes serve different
   admission checks.

Apple documents the [notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).
This builder does not implement the signing/notarization pipeline, PKG installation,
guided consent, `SMAppService` registration/approval, authenticated readiness,
identity/binding migration or secure updates. Existing macOS `enroll` and `serve`
remain explicit administrator interfaces. Do not install this draft as a completed
end-user enrollment flow. An installed release needs its final signed executable
to perform enrollment itself so its System-keychain application ACL matches the
same executable when the daemon starts.

## Verification

Portable tests reject incompatible Mach-O containers/targets and ambiguous CLI or
version input. Native tests exercise unchanged source bytes, private output,
symlink/permission rejection, source/path replacement, same-length byte changes
with restored timestamps, cancellation and competing publication. They also copy
the actual compiled test executable, decode both property lists using `plutil`,
apply a temporary ad-hoc app signature and verify it with `codesign --strict`.
Changing the daemon plist must then fail native code verification. These ad-hoc
tests establish a resource seal only; they do not establish Developer ID,
notarization, service registration, endpoint connectivity or hardware acceptance.

`scripts/check-macos-bundle.sh` builds the actual production agent, invokes the
public builder CLI, compares its copied executable byte-for-byte and validates
both generated plists. It removes its own temporary output and never runs the
agent or changes launchd, installed apps, OS trust or keychains. CI runs this check
on macOS alongside the native package tests and existing enrollment checks.
