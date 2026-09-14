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

The alternate socket/PID helper is package-private and used only by owned native
fixtures. These socket tests authenticate a synthetic D-Bus peer. A separate
[owned virtual machine fixture](linux-systemd-definition.md) now authenticates
actual systemd PID 1 and checks resolved definitions and canonical publication.
Protected enablement, configuration, registration, startup and authenticated
readiness remain controller integration work. Linux `activate` remains
unavailable until those requirements are joined.

The transport follows the Linux [Unix socket credential interface](https://man7.org/linux/man-pages/man7/unix.7.html),
the kernel's [descriptor namespace](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
and systemd's [direct private connection protocol](https://github.com/coreos/go-systemd/blob/main/dbus/dbus.go).
