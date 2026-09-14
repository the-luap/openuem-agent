# Authenticated Linux service readiness

The Linux agent publishes local readiness only after initial job registration and
scheduler initialization succeed. It uses the completed identity's broker signing
key and separate installed-agent binding. Initialization errors prevent readiness;
shutdown closes the endpoint and joins every signing request before releasing
the borrowed key. This component connects Linux runtime initialization to the
existing readiness protocol. Native service registration/activation and physical
installation acceptance remain separate work.

## Protected local endpoint

`localready.Listen` and `Probe` require root, a valid unexpired identity, and a
canonical identity directory with mode `0700`. Every ancestor is opened through
retained directory descriptors with `O_NOFOLLOW`. All directories must be owned
by root without group/other writes or special permission bits. Namespace identity
and permissions are rechecked during operation.

A root-owned, single-link `0600` lock file provides exclusive listener ownership.
An independently generated UUID in a private immutable address record selects
the socket name. Publication uses a complete synchronized temporary file and
`renameat2(RENAME_NOREPLACE)`; an existing record is never overwritten. Address
syntax, original metadata and ownership are checked before responses. Linux
identity storage preserves this runtime evidence if its credential subtree is
missing; a surviving endpoint cannot silently authorize fresh enrollment.

The endpoint is a filesystem Unix stream socket inside the retained identity
directory, with root ownership and mode `0600`. Both binding and probing use an
internally constructed `/proc/self/fd/<directory-fd>/<socket-name>` path. The file
descriptor is owned by this operation, and the basename comes only from verified
address metadata. This keeps operations inside the retained directory and avoids
the short Unix socket pathname limit for long canonical installation paths.
The canonical ancestor chain is still checked before and after exchanges.
[Linux file descriptor paths](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)

Clients and servers verify the peer's root UID and positive PID with the kernel's
`SO_PEERCRED`. The signed response must match that exact PID, the fresh random
nonce, device/organization/site identity, release digest, executable size/hash
and certificate expiry. A root process with a different key or identity cannot
substitute its own readiness response. The protocol carries no management command
or enrollment secret. [Linux Unix socket peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html)

## Lifetime and conflict handling

The listener starts not-ready. The Linux runtime invokes the shared scheduler
admission before marking it ready, and joins the endpoint before destroying its
identity on stop. Probes have a two-second context/socket deadline. The server
limits simultaneous requests to eight and refills at most eight request slots per
second. It rechecks native authority immediately before and after signing, so a
directory change during a blocked signature cannot produce an accepted response.

An active existing socket wins; it is never unlinked. Only an inactive socket at
the installation's verified address can be reclaimed, after native type, owner,
permissions and exact inode checks. Cleanup uses the retained directory descriptor
and removes only the current operation's socket inode. A changed namespace or
replaced object is preserved. Immutable lock/address metadata remains for restart.
Closing joins disconnected clients, cancellation callbacks and in-flight signing.

Local readiness means initialization completed, including offline reconnect
scheduling. Broker connectivity, inventory delivery and successful remote
management must still be verified through the management console.

## Native verification

`scripts/check-linux-readiness.sh` runs the real transport and agent lifecycle
race suites in a disposable Linux container with no network and a read-only
filesystem. Private tmpfs contains all endpoint data. A separate owned tmpfs holds
an unprivileged helper; a UID 65534 child reaches a deliberately public test socket
to prove the kernel peer-credential check rejects it independently of filesystem
access. No host service, endpoint identity or installed configuration is changed.

Required test families cover initial/not-ready transitions, signed identity and
key mismatches, singleton ownership, changed ancestry/permissions/hardlinks,
replacement preservation, active/inactive socket conflicts, native PID mismatch,
bounded silent/canceled probes, concurrent close, disconnected clients and joined
signing. Authority is changed while signing is deliberately held. A native
scheduler fixture verifies readiness follows initialization and disappears on stop.

The native transport suite passes in 4.145 seconds; the Linux agent, service and
shared lifecycle suites pass in 28.158/3.089/1.028 seconds, including the required
native scheduler/readiness integration. The separate full native
enrollment suite passes in 6.464 seconds, including actual DEB/RPM verification,
encrypted identity persistence and successful readiness authentication using the
stored device key. Its long canonical identity path also exercises descriptor-
based socket access. macOS transport/agent/lifecycle/service/activation regressions
pass in 1.646/28.136/2.324/4.143/4.468 seconds. Linux readiness/enrollment Vet passes.
