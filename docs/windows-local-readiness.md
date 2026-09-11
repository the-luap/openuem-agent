# Authenticated Windows agent readiness

An individual Windows agent with a protected executable binding publishes a local
readiness endpoint after configuration and initial job registration succeed. It
marks the endpoint ready after starting the scheduler. Legacy and earlier unbound
identities do not publish it. An initialized offline reconnect schedule can be
ready; remote connectivity, inventory delivery and compliance remain separate
console observations.

The service controller must accept SCM stop/shutdown while recovering an unresolved
identity, so it reports `Running` before any Agent is available. Activation also
requires a fresh signed readiness response from the exact SCM process and rechecks
that process, service configuration and installed image before reporting success.
A recovering controller, a different process or an old identity cannot satisfy it.

## Local transport and authority

`internal/localready` uses Microsoft's pinned `go-winio` 0.6.2 for namespace
reservation, connected I/O and client dialing, with an owned native connection
acceptance loop and a persistent shutdown event.
The public listener requires Local System; the probe permits Local System or an
elevated administrator. A protected installation directory contains an immutable
random pipe address, retained across ordinary restarts and process crashes. Final
reparse points, hard-linked address files, untrusted owners and public file access
are rejected. Retained directory/address handles exclude deletion/replacement and
address writes; kernel file IDs and permissions are rechecked during use. Trusted
installation ancestors remain the installer's responsibility.

The listener reserves the first named-pipe instance exclusively, rejects remote
clients and preserves an existing endpoint. Its System-owned descriptor grants
System full access and administrators individual client rights. Administrator
client rights exclude `FILE_CREATE_PIPE_INSTANCE`; generic write would include
that right. The client opens with anonymous impersonation level. These choices
follow Microsoft's
[named-pipe access contract](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
and [pinned transport implementation](https://github.com/microsoft/go-winio/blob/v0.6.2/pipe.go).
They do not attest a compromised privileged administrator.

Both sides inspect native peer process/token information. The client requires a
live Local System peer and its kernel-reported PID; activation also binds that PID
to SCM. It retains a process handle throughout the exchange. A duplicate pipe
handle makes native metadata checks safe across cancellation of the I/O connection.
See Microsoft's
[server process identification API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid).

The shared protocol signs a fresh 32-byte nonce, PID, device/tenant/site, release
digest, admitted executable size/hash, certificate deadline and readiness state
with the protected broker key. The canonical response is bounded to 2 KiB plus
framing/signature. It exposes no private key or invitation and accepts no
management commands. Wrong identity, signature, PID or nonce cannot establish
readiness.

## Lifetime and recovery

One exchange has a two-second deadline. The server admits at most eight concurrent
requests and eight requests per second with a burst of eight. Cancellation closes
the listener and accepted connections. Joined shutdown waits for every handler
before releasing the borrowed signing key and native directory handles. It does
not promise to interrupt an uncooperative signing implementation.

Native CI at `f3f1325798db896357e973f0b684633f68d19300` captured an intermittent
shutdown hang: `win32PipeListener.Close` waited on `doneCh` while its listener
routine had returned to the outer accept/close select. In the pinned dependency,
an unexpected connect error can override the close notification that was already
consumed. This trace has no pending native connect operation; it is distinct from
the proposed stalled-I/O explanation in [upstream issue 357](https://github.com/microsoft/go-winio/issues/357).

The readiness listener now keeps the exclusive disconnected namespace instance
idle and owns only pending `ConnectNamedPipe` operations. A manual-reset stop
event remains signaled regardless of the connect result. Shutdown cancels and
drains the exact outstanding operation, joins acceptance, and then closes the
namespace anchor and event. Accepted connections retain the same private
descriptor, remote-client rejection and connected I/O behavior. No timeout
abandons a listener or borrowed signer. The implementation follows Microsoft's
[overlapped pipe contract](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-overlapped-i-o)
and [cancellation lifetime requirements](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex).

The pipe disappears when its owning handles close, including on process exit;
the address record remains. Partial/invalid address publication fails closed and
is retained for inspection. No automatic address deletion, identity replacement
or foreign endpoint cleanup is performed. Activation cancellation preserves the
service and identity, and the controller remains stoppable. A subsequent retry can
observe the initialized generation using the same protected identity.

## Verification scope

Portable protocol and agent lifecycle tests cover signed identity/nonce/PID bounds,
startup ordering, incomplete readiness and joined key ownership. Native Windows
tests exercise private pipe/file permissions, singleton ownership, changed scope
or signing key, wrong PID, partial address retention, competing writes, idle
clients, held signing operations and process-crash recovery. The public listener
rejects ordinary non-System test processes.

A separate native race job requires all readiness fixtures without skips. The
shutdown regression performs 96 owned namespace cycles across idle listeners,
pending connections and immediately disconnected clients, including concurrent
and repeated close and reopening the same namespace after every joined stop.
Windows AMD64/ARM64 compilation and Windows vet pass; portable protocol race
tests pass in 1.673 seconds. The native race job passes at
`589bf1b7e872984896307ccd185d57601c49b0b5`: all 96 shutdown cycles finish in
0.34 seconds, alongside the existing identity/PID, permission, held-signer and
crash-recovery checks. The separate full storage/SCM run failed before tests when
the Go module proxy interrupted a dependency download; its integration rerun
remains outstanding.

Owned, uniquely named Local System SCM fixtures additionally load actual DPAPI
identities and publish production readiness proofs. They verify that SCM `Running`
with `ready: false` never completes activation, that a foreign SCM PID fails, and
that stop/restart recovery preserves identity records. They construct the actual
individual agent but do not start inventory, broker traffic or host-management
tasks. These synthetic tests do not establish signed-installer or physical-device
acceptance.
