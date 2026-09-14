# Persistent Linux service registration

The Linux controller admits the protected canonical unit and enablement link
before connecting to the root PID-1 private manager. `Open` and `Status` resolve
the full unit search path without publishing, enabling or starting a service.
An existing vendor definition, loaded foreign configuration, or enabled state
without the canonical protected link fails before publication.

`Register` publishes the canonical unit exclusively, synchronizes the retained
file and directory, reloads manager metadata, and enables only
`openuem-agent.service`. Both runtime and force arguments are false. The reply
must describe at most the canonical persistent symlink; filesystem admission
and synchronization independently verify that link. A final reload and typed
observation establish persistent registration. Registration never starts,
restarts, stops, disables, unmasks or resets a service.

Canonical files left before a reload or after enablement can be resumed. An
already enabled retry verifies and synchronizes the existing state without
repeating mutating manager calls. Conflicts and uncertain outcomes preserve all
published evidence. Closing interrupts pending manager calls, joins the
serialized operation and releases descriptors without unregistering anything.

The native race fixture covers initial and resumed registration, concurrent
callers, malformed replies, foreign definitions and links, changed files,
cancellation and a manager that withholds its reply. The RAM-only systemd
fixture requires all registration scenarios on three fresh boots. It verifies
that registration leaves the unit inactive with no process, invocation or start
timestamp. Enabled inactive units may be garbage-collected by systemd, so this
check resolves metadata again instead of treating a `GetUnit` cache miss as
evidence of absence.

Registration alone does not implement the complete Linux activation command.
The [start controller](linux-systemd-start.md) provides process-bound signed
readiness. Protected operational configuration and CLI integration must still
be joined before enabling that platform path.
