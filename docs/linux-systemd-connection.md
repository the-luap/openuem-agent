# Native Linux systemd connection

The internal `linuxservice` connection opens only `/run/systemd/private` in
production. It does not consult environment-selected bus addresses or execute
`systemctl`. Before sending authentication bytes, it checks the connected Unix
socket's kernel `SO_PEERCRED`: the peer must have UID 0 and PID 1. A root-owned
socket served by an ordinary root process or an unprivileged process fails.

Every root-owned directory from `/` to the socket's parent is retained with
no-follow descriptors. Writable or special-mode ancestors fail. The socket is
retained separately with `O_PATH`; it must be root-owned, single-linked and a
socket, with unchanged metadata and namespace. The internally constructed
`/proc/self/fd/<parent>/private` connection path also supports long canonical
fixture paths. The connection never removes, replaces or changes its socket.

The pinned `github.com/godbus/dbus/v5` dependency performs EXTERNAL authentication
on the already verified stream. The systemd private peer requires no bus `Hello`
and this connection does not send one. Authentication has a five-second deadline
and a 16 KiB total input bound, including unterminated lines. Binary messages use
the dependency's codec and bounds; the authentication limit is not a claim about
binary property message size. Peer-controlled authentication and method error
bodies are not exposed to callers.

After writing `BEGIN`, authentication waits for Linux `TIOCOUTQ` to report that
the Unix stream's queued bytes have been consumed. This prevents the first binary
message from arriving in the same authentication read, an observed systemd 252
event-loop stall. The check uses the existing authentication deadline and caller
lifetime; it adds no protocol bytes, bus `Hello`, fixed sleep or speculative call.
The one-millisecond poll only schedules another kernel queue check. A stalled,
canceled or closed peer cannot extend the five-second authentication ceiling.

Internal calls recheck the retained socket and ancestry before sending and after
receiving a result. Each call has a five-second ceiling and honors earlier caller
cancellation. Cancellation closes the raw stream independently of the library's
output lock, so a blocked write cannot prevent shutdown. Close rejects new calls,
interrupts the transport, joins active calls and cancellation callbacks, then
releases the retained namespace. A canceled call invalidates this connection;
callers must obtain a new admitted connection for subsequent work.

## Validation and remaining integration

`scripts/check-linux-service-unit.sh` runs the package under the race detector in
a read-only, network-isolated Linux container with owned tmpfs fixtures. Required
test families exercise:

- Native systemd parsing of the separate [unit contract](linux-service-unit.md).
- Actual Unix sockets, both EXTERNAL handshake forms and decoded D-Bus method
  replies, with no bus `Hello` and no environment-selected endpoint.
- PID mismatch before any authentication byte; an actual UID 65534 helper whose
  socket is subsequently made root-owned still receives no authentication bytes.
- Unsafe or replaced directories/sockets, hard links, namespace changes during
  authentication and after the request but before the reply.
- Malformed, rejected, unterminated, canceled and silent authentication; redacted
  peer errors; call deadlines, lifetime cancellation and concurrent close.
- A blocked binary write to a peer that remains open and does not read until
  after the client has returned, proving cancellation independently of peer exit.
- An unread `BEGIN` marker that prevents authentication completion until actual
  peer consumption; deadline, cancellation and closed-stream interruption.

The alternate socket/PID helper is package-private and used only by owned native
fixtures. These socket tests authenticate a synthetic D-Bus peer. A separate
[owned virtual machine fixture](linux-systemd-definition.md) now authenticates
actual systemd PID 1 and checks resolved definitions and canonical publication.
Protected [enablement](linux-systemd-enablement.md) now has separate native and
live-manager checks. Configuration, registration, startup and authenticated
readiness remain controller integration work. Linux `activate` remains
unavailable until those requirements are joined.

The transport follows the Linux [Unix socket credential interface](https://man7.org/linux/man-pages/man7/unix.7.html),
the kernel's [descriptor namespace](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
and systemd's [direct private connection protocol](https://github.com/coreos/go-systemd/blob/main/dbus/dbus.go).

## Complete-message cancellation boundary

An actual AMD64 guest exposed a godbus 5.2.2 panic when closing the socket during
header/body alignment. Its generic decoder aligns outside the decoder recovery
boundary. The manager transport now admits a complete message before handing
any of its bytes to godbus. Lengths use overflow-safe arithmetic, allocation is
bounded to 1 MiB, and a local decoder boundary rejects malformed complete frames.
Only admitted in-memory bytes reach the library's streaming decoder; cancellation
interrupts the next socket read without exposing a truncated alignment sequence.

The native regression holds the peer open after the kernel confirms consumption
of exactly the header prefix, then closes the controller while alignment bytes
are withheld. The pending call must join without panic. Oversized, overflowing
and malformed complete messages also fail. Authentication, the root PID-1 check,
namespace retention and existing deadlines remain required. The relevant library
code is [DecodeMessageWithFDs](https://github.com/godbus/dbus/blob/v5.2.2/message.go).
