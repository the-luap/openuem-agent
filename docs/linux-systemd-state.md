# Loaded Linux service state

The internal systemd observer reads only the fixed OpenUEM agent object through
the [authenticated private connection](linux-systemd-connection.md). It uses
`GetUnit` followed by typed `Properties.GetAll` reads. Observation never loads,
reloads, enables or starts a unit. A manager's `NoSuchUnit` response means the
unit is not loaded; it does not establish that its file is absent.
The separate [definition resolver](linux-systemd-definition.md) uses `LoadUnit`
to check the complete manager search path before any new publication.

Admission requires the fixed unit ID/name and canonical fragment path, no source
override, no aliases or drop-ins, no transient definition and no pending daemon
reload. Every required property must be present with its exact D-Bus signature;
missing booleans, empty lists or numeric values cannot become accepted defaults.

The effective service must retain the canonical root user/group, exec type,
restart/stop/kill behavior, umask and PATH. Alternate roots/images, environment
files, inherited/unset environment directives, PID files and PAM settings fail.
Its one `ExecStartEx` command must preserve the admitted literal executable and
identity arguments and only the `no-env-expand` execution flag. Additional
condition, startup, reload or shutdown commands fail.

A running observation requires matching main/exec-command PIDs and nonzero
monotonic start times, a nonzero invocation ID and no recorded command exit.
Never-started services may have the empty invocation array emitted by systemd;
that representation cannot authorize a running observation.
Unsupported state combinations, an active-but-exited process, runtime-only
enablement, malformed jobs and out-of-range PIDs fail. Inactive, failed and known
startup/shutdown states are separate observations, not readiness success.

Unit properties are read again after the service properties. The same contract
must still hold, including state-change timestamp, invocation and job identity.
The observer returns only an admitted typed snapshot, or an error with no
peer-controlled diagnostic body. A future controller must additionally retain
the [protected unit file](linux-unit-publication.md) and compare snapshots around
the device-signed, kernel-PID-bound readiness probe.

Common race tests pass in 1.423 seconds. They cover every missing/wrongly typed
required property, changed service settings, literal arguments, execution flags,
all extra executable hooks, and inconsistent runtime identities. Native Unix
socket/D-Bus codec fixtures verify the exact read-only call sequence, missing and
foreign objects, malformed replies and changed properties between reads. The
complete native unit/connection/publication/state race suite passes in 7.322
seconds. Separate [RAM-only virtual machines](linux-systemd-definition.md) now
verify actual PID-1 authentication, canonical publication and loaded/absent/vendor
definitions. Registration and activation are not yet covered by these tests.

Property types follow systemd's published
[unit interface](https://github.com/systemd/systemd/blob/v252/src/core/dbus-unit.c),
[service interface](https://github.com/systemd/systemd/blob/v252/src/core/dbus-service.c)
and [extended command signature](https://github.com/systemd/systemd/blob/v252/src/core/dbus-execute.h).
