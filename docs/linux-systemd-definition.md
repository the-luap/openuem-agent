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

Each fresh guest must pass all four tests: actual private-manager authentication,
resolved absence, publication/loading of the canonical never-started definition,
and rejection of an actual vendor definition without creating an override. A
failed boot or test stops the runner; the three boots are required repetitions,
not automatic retries. Guest mutation tests additionally require the explicit
environment, file and kernel markers, a RAM root filesystem and systemd PID 1.

All three local ARM64 guests passed using Debian systemd 252.39 and Linux 6.1.
An earlier fixture run had one five-second lookup timeout; its precise cause was
not established. The runner now uses `Type=exec` so manager startup can finish
while tests execute, and errors include a static RPC phase without peer payloads.
The production timeout has not changed. CI runs the same required guest tests on
AMD64; its result must be checked independently.

These tests do not yet start the agent. Protected enablement, operational
configuration and the controller's registration/start/readiness sequence remain
integration work. Linux `activate` remains gated until those providers are joined.

The resolution behavior follows systemd's
[LoadUnit handler](https://github.com/systemd/systemd/blob/v252/src/core/dbus-manager.c)
and [manager load implementation](https://github.com/systemd/systemd/blob/v252/src/core/manager.c).
The fixture uses QEMU's [ARM virt board](https://www.qemu.org/docs/master/system/arm/virt.html)
and [direct kernel boot](https://www.qemu.org/docs/master/system/linuxboot.html).
