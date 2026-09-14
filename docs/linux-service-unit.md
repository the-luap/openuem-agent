# Linux systemd unit contract

`internal/linuxservice` renders one exact `openuem-agent.service` definition from
the already admitted executable and protected identity directory. This is the
unit-definition component of Linux activation. It does not publish a system unit,
enable/start a service or authorize an existing manager configuration. Native
file ownership, effective systemd metadata, registration, main-process binding
and readiness still require the activation controller.

The unit runs the executable directly as root with only `serve` and the explicit
identity-directory argument. It fixes `Type=exec`, a private umask, bounded stop
time, mixed process-group shutdown and restart on failure. Its install target is
`multi-user.target`; callers cannot provide another unit name, account, command,
environment or startup hook. The fixed operational directories match the existing
Linux runtime: `/etc/openuem-agent` and `/var/log/openuem-agent`.

Canonical absolute paths must be valid UTF-8, bounded to 4096 bytes and free of
control characters. The executable cannot reside inside the identity directory.
Systemd's native parser also rejects executable names containing quotes or
backslashes; the specification rejects those before rendering. Directory
arguments can contain such literal characters and are quoted appropriately.
Percent signs are doubled to prevent specifier substitution. The `:` execution
prefix disables environment expansion, preserving literal dollar expressions
without invoking a shell. These rules follow the native
[systemd command parser](https://github.com/systemd/systemd/blob/v252/src/core/load-fragment.c)
and [service command syntax](https://github.com/systemd/systemd/blob/v252/man/systemd.service.xml).

`Matches` compares the complete canonical unit bytes. A matching marker comment
or command line cannot admit another account, additional startup commands,
a different identity path or weakened lifecycle settings. Matching text still does
not prove ownership or rule out effective drop-ins; the future controller must
check those separately.

`scripts/check-linux-service-unit.sh` uses a disposable read-only Linux container
with private tmpfs mounts. The real `systemd-analyze verify` reads only the owned
unit tree under an explicit root, with generated inert target definitions and an
unexecuted copy of `/usr/bin/true`. Native verification checks ordinary and literal
paths, inspects decoded service/argument metadata and rejects missing executables
or unapproved startup hooks. No live systemd manager or host service is changed.
The checker needs its own writable `/tmp`; that mount is private and non-executable.
[Native offline unit verification](https://github.com/systemd/systemd/blob/v252/man/systemd-analyze.xml)

Unit tests additionally reject noncanonical/control-character paths, alternate
identity roots, extra directives and oversized definitions. Fuzzing exercises
bounded path rendering and its single-command contract. This evidence does not
establish successful service installation, runtime activation or physical-device
acceptance.

The full native unit race suite passes in 1.034 seconds with actual systemd
252 parsing. The macOS unit race suite passes in 1.379 seconds; bounded path
fuzzing passes 691,399 executions. Complete Linux and Windows agent builds pass.
CI runs this fixture and path fuzzing alongside native Linux readiness.
