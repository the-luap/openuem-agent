# Linux individual-service ownership

`enrollmentstore.AcquireServiceLease` provides the Linux process-ownership
primitive for a private individual installation. It is independent of identity
storage, package trust and service activation. Linux `OpenNative` remains
unsupported until protected credential storage is implemented; a lease alone
cannot enroll an endpoint or enable the individual service.

The caller must be root and supply an existing canonical absolute installation
directory with mode 0700 and root ownership. Every ancestor from `/` must also be
root-owned, without group/other write access or special mode bits. Shared sticky
directories are refused. The implementation walks with descriptor-relative
`openat`, refuses symlinks and retains all ancestor descriptors. It creates no
installation directory and repairs no permissions.

The persistent `.openuem-service.lock` must be an empty, root-owned regular file
with mode 0600 and exactly one link. Nonblocking native opens reject unsuitable
objects without waiting on a FIFO. A nonblocking exclusive `flock` admits one
process; independent handles and other processes receive `ErrServiceBusy`. The
file and its parent directory are flushed before ownership is exposed.

Every validation checks the retained directory chain, current root namespace,
private directory and exact lock inode. Replacement, permission changes, extra
links or added content invalidate ownership. `ValidateDirectory` also binds the
lease to the originally selected installation. Close joins concurrent validation,
closes the lock and every retained descriptor, and never unlinks the lock file.
Kernel ownership ends when the owning process exits, allowing explicit startup
recovery against the same permanent empty file.

Privileged root remains inside the trust boundary. This primitive does not prove
that an orphaned native operation has ended and does not replace operation
journals, current recipient validation or the separate uncertainty barriers.

## Owned validation

Linux fixtures run in disposable containers with networking disabled, read-only
root/source mounts and a private root-owned temporary filesystem. They cover
cross-process exclusion, owner termination, twelve competing handles, concurrent
close/validation, unsafe and replaced ancestors, symlinks, hardlinks, FIFO/socket
objects, permissions and preserved data. A separate unprivileged process verifies
that rejection creates no lock. No host service or identity store is touched.

The common lease-close regression also runs on macOS; the Windows storage test
binary is cross-compiled to check the shared lifecycle change. Native Windows
execution is separate from that compilation evidence.

The dedicated `linux-service-ownership` CI job runs
`scripts/check-linux-service-ownership.sh` after dependency caching. It compiles
with the race detector inside Go 1.26.8 on Debian Bookworm, then runs the root
ownership matrix and a separate `nobody` process inside the same disposable
container. The existing unprivileged Linux job also runs the rejection test.
The local full Linux enrollment-store race suite passed in 83.263 seconds;
macOS lease regressions passed in 2.507 seconds. The Windows test binary compiled.
