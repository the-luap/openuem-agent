# Protected Linux bootstrap package staging

`bootstrapinstall.StagePackage` now connects signed Linux bootstrap/release data,
exact-origin HTTPS downloads and [native DEB/RPM publisher verification](linux-package-signatures.md).
It accepts only the running Linux architecture and exact signed artifact. A package
is returned only after the download is flushed, its complete signed size/hash is
verified, its native publisher is accepted, and the same opened bytes are checked
again against the protected release checkpoint and lifetime.

This prepares a package. It does not install it, run package scripts, claim an
identity, persist an invitation or activate a service. The installed Linux
enrollment/activation commands and production installation acceptance remain
separate work. The [running-image provider](linux-running-executable.md) verifies
the independent installed-agent binding; an installer hash cannot replace it.

## Directory ownership and admission

Linux staging requires root and an existing canonical 0700 staging root under
root-owned ancestors with no group/other write permission or special mode bits.
Before any HTTP request or staging creation, it opens and retains the entire path
from `/` without following symlinks. It rejects shared roots, writable ancestors,
untrusted owners and symlink ancestors without downloading or repairing anything.

Each preparation creates its own private `package-<UUID>` directory relative to
the retained root descriptor, then retains that exact directory as well. Ancestor
and root/stage directory identities remain checked throughout the operation.
Other preparations may create and remove their own sibling directories without
invalidating this owner. The native verifier independently checks the protected
candidate and publisher prerequisites.

The signed artifact filename is created exclusively with 0600 permissions. The
writer is closed before native verification, and a read-only descriptor retains
the original file identity. Linux checks require a root-owned, single-link regular
candidate. `Package.Verify` rechecks that file, the complete directory chain,
signed bytes, artifact/target, checkpoint and lifetime. `Path` returns no path if
the retained directory/file identity is no longer valid. A returned path remains
an address, not an authorization token; verify immediately before eventual use.

## Conservative cleanup

Close is serialized with verification and releases all file/ancestor handles.
Cleanup acts relative to the retained stage/root descriptors and only on the
original file and exact stage-directory identities. It removes no ancestor and
never recursively walks staging. An unrelated file, replacement root/stage/file,
hardlink or unsafe metadata prevents successful cleanup and is preserved.
If only an extra unrelated file appeared, the owned package can be removed while
the nonempty stage and unknown file remain. Another preparation's directory is
never reused or removed.

Failed downloads, changed response bodies and native signature failures invoke
the same owned cleanup. Cancellation retains the common bounded HTTP/native
process behavior. A failure after creating a directory but before observing its
inode can leave a private fragment; automatic crash discovery/removal remains a
separate protocol. Root remains inside the trust boundary.

## Native verification evidence

The isolated package-signature CI fixture now runs the complete signature and
bootstrap-installation race suites together. It generates inert, genuinely signed
DEB/RPM files and independently signed bootstrap/release envelopes, serves their
bytes over certificate-pinned test HTTPS, and uses the production public staging
entry point. Every required native family must report a pass explicitly.

Tests accept authorized publishers for both formats and reject unsigned/foreign
publishers even when the release envelope correctly authorizes those bytes. They
reject response substitution, changed staged contents and later checkpoints;
verify no network or directory creation under unsafe roots; preserve replaced
namespaces, hardlinks and unknown files; and close independent owners safely.
No package is installed or executed, and no host trust or service state changes.

The combined native race suites pass: signatures in 5.518 seconds and complete
bootstrap staging/executable checks in 1.999 seconds.
macOS bootstrap, enrollment-command and activation-command race regressions pass
in 1.788/2.222/5.131 seconds. Full Linux/Windows agent builds and Linux bootstrap
Vet checks pass; the Windows bootstrap test binary cross-compiles.
