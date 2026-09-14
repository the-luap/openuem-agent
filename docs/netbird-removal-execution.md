# Native macOS NetBird removal execution

Individually enrolled root macOS agents now configure native removal inspection
and execution together. Support requires CGO, native ACL/code validation, macOS
11.3 or later and the audit-token signal and typed system-job APIs. Other builds
keep removal unavailable. The console still needs its separate reviewed removal
request, dispatch, recovery and UI lifecycle.

## Admission and execution ownership

The version-four command retains the exact source-free descriptor produced by
the [combined file/job/process observer](netbird-removal-runtime.md). Preparation
reconstructs that descriptor, compares complete filesystem evidence and retains
open descriptors without changing the installation. Execution also rejects
group-writable payloads, even when their admin ownership permits inspection.
Existing removal staging artifacts prevent a fresh preparation or readiness
claim; they cannot become disposable package downloads.

The service acquires the owner under the common executor mutex and requires the
same ready journal state before and after preparation. `BeginRemoval` durably
records the exact command before `Run`. The owner is single-use; execution,
cancellation and descriptor cleanup join before a result is persisted. A failed
native operation, changed evidence, deadline or failed cleanup remains
`unconfirmed`. Replaying the same command returns its original receipt before
acquiring an owner, including after the owner is no longer configured.

Read-only `removal-state` requires both inspector and execution owner. It returns
the exact descriptor or positive absence together with an unchanged journal
state. Busy execution blocks inspection. Read-only evidence can accompany an
unconfirmed journal for explicit recovery, but never releases that journal.

## Stopping the reviewed runtime

The execution owner rechecks the exact loaded job before the fixed system command
`/bin/launchctl bootout system/netbird`, then confirms the job is unloaded. It
signals only reviewed process instances after revalidating their audit generation,
executable path and running code. The fixed native signal primitive uses the
complete kernel audit token; it never falls back to a PID or process name.

SIGTERM receives a bounded exit interval. Only expiry of that interval permits
revalidated SIGKILL; a failed identity or liveness query does not. Explicit typed
job queries and complete process enumeration must then show quiescence. No
NetBird CLI, shell removal command or vendor uninstall script runs in this path.
The fixed OS utility runner uses a clean environment, discards diagnostics and
joins cancellation of the utility it started.

## Protected file removal

After journal admission, the owner creates a root-owned mode-0700 directory
`/Applications/.openuem-netbird-removal-<request UUID>` using protected directory
descriptors. Its mode-0600 manifest records the original UUID, reviewed descriptor
and private object metadata/hashes. It contains no service plaintext, credentials
or package source. The manifest and directory entries are synchronized before
the first source move.

The verified app, optional CLI symlink and optional daemon plist move into that
private directory using descriptor-relative exclusive renames. No destination is
overwritten. The entire relocated tree must match the original evidence, allowing
only the moved root's rename-induced ctime change. If an unreviewed replacement
was relocated, the owner attempts an exclusive restore into the same protected,
empty source slot; otherwise it preserves the object in staging. It never deletes
an object it cannot identify.

Before deletion, complete quiescence includes both original and staged executable
paths. Every recorded file/link is checked again before its individual unlink;
directories are removed only when empty. The owner uses no recursive blanket
deletion. Stable directory descriptors, ownership, ACLs and inode bindings protect
traversal; any unexpected entry or replacement causes an unconfirmed result.

Receipt files remain in the native receipt database. Their exact objects and
contents are rechecked before and after payload deletion, immediately before
the fixed command `/usr/sbin/pkgutil --volume / --forget io.netbird.client`.
The owner never treats removal of a receipt as proof that payload or runtime
state is absent. Configuration, credentials, logs and provider peers remain
outside this operation.

## Positive absence and interruption

Completion requires all fixed app/link/plist/receipt paths absent through
protected ancestry, an explicitly unloaded system job, complete process scans
with no matching original or staged executable and an empty exact package-ID
query. These native checks repeat. The successful owner removes only its verified
manifest and empty staging directories, then performs final absence verification
which also rejects any retained removal stage.

Failure and cancellation preserve remaining staging evidence. `Close` only closes
owned descriptors; preparation expiry, restart and explicit journal release do
not erase it. Retained staging requires separately reviewed local recovery before
another removal can be prepared. This implementation does not provide automatic
rollback, stage cleanup or a console stage-recovery workflow. Final-query failure
can leave an unconfirmed receipt after files are already absent; later read-only
inspection still does not rewrite that original receipt.

## Verification and limits

Owned filesystem fixtures cover successful app/link/plist removal, optional absent
objects, preserved configuration/logs/unrelated apps, read-only preparation,
exclusive destination collisions, restored changed subtrees, altered staging,
receipt races, retained receipts, cancellation, running processes, later source
replacement, failed native results and retained-stage exclusion. Native process
tests ad-hoc sign an inert helper and verify that a signal for a changed audit
generation cannot hit it, while a genuine token terminates and joins that helper.
No host NetBird process, package, daemon or installed device is mutated by tests.

Real-broker service tests cover paired capability publication, stable inspection,
admission ordering, current identity, deadlines, rejected-plan cleanup and original
receipt replay without reexecution. Darwin race suites, owned Linux filesystem
tests, agent runtime regressions, Darwin/Linux/Windows agent builds and Darwin
without-CGO package compilation pass. Existing CI runs these test packages.
Physical package, interruption, reboot and interactive-desktop acceptance remains
required, as does Linux individual enrollment and independent publisher trust.

## Primary references

- [Apple exclusive descriptor-relative rename semantics](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/rename.2)
- [Apple audit-token process APIs](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c)
- Native macOS `pkgutil --help` documents exact package queries, root-volume
  selection and receipt removal independently of installed files.
