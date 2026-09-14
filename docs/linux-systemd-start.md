# Linux service start and authenticated readiness

The controller starts only the admitted, persistently enabled canonical unit.
`StartUnit` receives its fixed name and job mode `fail`, so it cannot replace a
conflicting queued job. A reply must carry one canonical, positive 32-bit job
object path. An already running invocation is observed without another start.
Stopping, restarting, resetting failures and unmasking are not controller APIs.

Successful activation requires a device-signed readiness response from the exact
main PID reported by the root PID-1 manager. The controller retains and rechecks
the unit file and persistent link, validates the complete effective definition,
then fences the probe with typed runtime observations. PID, invocation ID, both
monotonic start timestamps, state-change timestamp, enablement and job state must
remain unchanged. A process replacement, foreign key/device identity, definition
change or pending conflicting job cannot be reported as readiness.

systemd records the command and main-process start timestamps separately. The
command timestamp must be nonzero and no later than the main-process timestamp;
both remain part of the readiness fence. This ordering follows
[`exec_spawn`](https://github.com/systemd/systemd/blob/v252/src/core/execute.c)
and the subsequent
[`service_set_main_pid`](https://github.com/systemd/systemd/blob/v252/src/core/service.c)
call, and is exercised against real systemd rather than assumed equal.

A normal startup transition can occur between the unit/property reads. The controller may
wait and read again before binding a running process only when it has one fully
admitted snapshot, valid typed runtime metadata on the other side, and the same
admitted configuration. A service sample can fall on either side of the unit
transition; no mixed snapshot is returned as process evidence. Missing or malformed
properties never enter this retry path. Once readiness probing begins, any
changed invocation fails, including after an authenticated not-ready response.

The wait has a two-minute ceiling and honors earlier cancellation. Closing the
controller cancels pending readiness work and manager calls before joining the
operation lock. It preserves the running process, registered unit and identity.
A canceled manager call invalidates its connection; recovery opens a fresh
controller and admits the retained state again.

The native race fixture requires 22 test families. Start tests exercise actual
Unix/D-Bus codec exchanges and signed root readiness sockets, including startup
transitions, changed PID/timestamps/invocation/jobs/files/links, foreign identity
and key, initialization, malformed jobs, and cancellation of withheld manager
or readiness replies. The separate RAM-only fixture requires seven families on
three fresh virtual-machine boots. A marker-gated helper is launched through the
canonical unit, proves signed readiness, rejects mismatched identity and remains
running after retries, failed readiness, timeout or controller close. Only the
guest test cleanup stops that freshly admitted helper.

The Linux activation CLI still requires protected operational configuration and
integration with the enrolled identity and admitted executable. This controller
does not supply production publisher provisioning or physical device acceptance.
