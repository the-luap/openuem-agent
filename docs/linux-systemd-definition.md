# Resolved Linux service definitions

The internal `loadDefinition` operation resolves `openuem-agent.service` through
the authenticated PID-1 systemd manager before a controller may publish a new
unit. `GetUnit` only searches loaded objects: its `NoSuchUnit` error cannot prove
that a vendor service is absent from another systemd search directory.

`LoadUnit` resolves the manager's complete search path without starting a service.
The response must name the fixed OpenUEM unit object. Typed Unit, Service and Unit
property reads then admit either the canonical loaded definition or a strictly
absent definition. An error response, malformed object or incomplete property
map never becomes evidence of absence.

Absence requires `LoadState=not-found`, the exact unit ID/name, empty fragment,
source, enablement and drop-in properties, no transient definition or pending
reload, inactive/dead state, no job, no main or retained process/start timestamp,
and no executable hooks. The invocation byte array must be empty. The final Unit
read must retain the same admitted classification and state-change timestamp.
Foreign vendor files, aliases, masks, commands and changing observations fail.

Actual systemd exposes an empty `ay` InvocationID for a never-started service.
The loaded-state parser also accepts this representation before running. A
running observation still requires the nonzero 16-byte invocation ID and matching
main/command PID and monotonic start time.

## Validation

`scripts/check-linux-service-unit.sh` requires native D-Bus codec tests for fixed
`LoadUnit` resolution, canonical and absent definitions, foreign objects/vendor
files/aliases, malformed replies, retained commands and changes between reads.
The common parser tests reject every missing or incorrectly typed required
property and each retained executable hook.

`scripts/check-linux-systemd.sh` boots three independent RAM-only virtual machines
using QEMU's software CPU emulation. Each guest has its own kernel, cgroup tree
and actual root systemd PID 1. The outer container is read-only, has no network
and drops all capabilities. No host cgroup, device or filesystem is mounted into
the guest. No privileged container or host service mutation is required.

Each fresh guest must pass all five tests: actual private-manager authentication,
resolved absence, publication/loading of the canonical never-started definition,
actual persistent [enablement](linux-systemd-enablement.md), and rejection of an
actual vendor definition without creating an override. Authentication uses twenty
new connections per guest, each with an immediate first property call. A
failed boot or test stops the runner; the three boots are required repetitions,
not automatic retries. Guest mutation tests additionally require the explicit
environment, file and kernel markers, a RAM root filesystem and systemd PID 1.

Local ARM64 guests use Debian systemd 252.39 and Linux 6.1. Initial local and AMD64
CI runs exposed intermittent first-call timeouts. An owned PID-1 syscall trace
showed `BEGIN` and the first binary message arriving in one `recvmsg`; systemd
then waited in epoll until the client closed five seconds later. Debug logging
alone had misleadingly suggested a stall during unit resolution.

The [connection](linux-systemd-connection.md) now waits for kernel-confirmed
consumption of `BEGIN` before releasing authentication. It sends no additional
protocol bytes or method calls and retains the existing five-second bound.
Native fixtures independently verify that unread bytes block completion, actual
consumption releases it, and cancellation, close and deadline interrupt it.
The diagnostic strace attachment and debug logging were removed from the runner.
All five live tests pass in three fresh ARM64 guests after this change. CI runs
the same required guest tests on AMD64; its result must be checked independently.

These definition tests do not start the agent. The later
[Linux activation integration](native-linux-activation.md) joins operational
configuration and registration/start/readiness, with additional live families
that launch the owned helper through the canonical unit.

The resolution behavior follows systemd's
[LoadUnit handler](https://github.com/systemd/systemd/blob/v252/src/core/dbus-manager.c)
and [manager load implementation](https://github.com/systemd/systemd/blob/v252/src/core/manager.c).
The fixture uses QEMU's [ARM virt board](https://www.qemu.org/docs/master/system/arm/virt.html)
and [direct kernel boot](https://www.qemu.org/docs/master/system/linuxboot.html).
