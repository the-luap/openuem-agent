# Native service initialization and cleanup

The Windows service keeps its control loop available during initialization and
identity recovery. Linux and
macOS install SIGTERM/SIGINT handlers before constructing the agent. These are
service lifecycle changes. Windows now has a separate
[activation command](native-windows-activation.md) for configuration, registration
and startup after completed enrollment. macOS has a separate authenticated
registration/approval flow; end-user signed installer integration remains open.
The subsequent explicit `serve -identity-directory` selection is described in
[runtime configuration](individual-agent-runtime.md).

## Initialization

`agent.New(context.Context)` returns an error instead of terminating the process
on a missing or invalid protected identity, configuration, certificate or
scheduler. A failed constructor releases its partially initialized resources.
The individual runtime inherits the service context and still selects protected
state before reading any shared certificate configuration. No legacy fallback
is introduced.

`Start` returns configuration and job-registration errors. It registers the first
inventory report as an immediate scheduler task and starts the scheduler only
after registration succeeds. A temporary broker connection failure can still
start the existing reconnect job. An Agent readiness proof means local
initialization and work scheduling succeeded. Server reachability and inventory
delivery remain separate observations. Native SCM `Running` can also describe an
initialized controller whose identity recovery has not yet produced an Agent.

The common lifecycle runner serializes construction, start and cleanup. A stop
received during initialization cancels the context and waits for the initializer
to return before calling `Stop`. It never races cleanup against initialization
or announces readiness after an observed cancellation. Constructors transfer
ownership of a partially returned runtime for cleanup even when they return an
error.

Windows publishes `StartPending` with no accepted controls and a 30-second wait
hint for finite local initialization. A successfully initialized recovery
controller reports `Running` and accepts Stop/Shutdown while Agent readiness
remains unavailable. Local initialization failure reaches `StopPending` and a
service-specific exit code of 1. Stop/Shutdown publishes `StopPending`
immediately and keeps Interrogate handling available during cleanup. Interrogate
returns the service's current state, not a possibly stale status in the request.
Unsupported controls are ignored. Checkpoints cover finite initialization/cleanup;
network recovery stays in the stoppable controller state.
`svc.Run` reports `Stopped` after the handler has finished cleanup.

[Windows activation](windows-local-readiness.md) requires an authenticated local
readiness response from the exact live SCM process. It cannot infer Agent
initialization from SCM `Running`. macOS uses its authenticated Unix-socket proof.
Both endpoints close and join before a generation releases its signing key.

These transitions follow Microsoft's [ServiceMain guidance](https://learn.microsoft.com/en-us/windows/win32/services/service-servicemain-function)
and [service state rules](https://learn.microsoft.com/en-us/windows/win32/services/service-status-transitions).
The wait hint describes expected progress; it is not an enforced deadline for
every inherited operating-system operation.

## Cleanup ownership

Stop is idempotent for both service modes. It closes task admission, cancels the
service context, shuts down messaging/scheduling and joins admitted tasks before
releasing their protected identity or cache. This includes the asynchronous
report triggered by an enable command. A scheduler timeout is not mistaken for
completion of a still-running task. Repeated concurrent Stop calls wait for the
same cleanup.

The legacy SFTP loop now owns a context-bound listener, including cancellation
before the SSH server registers that listener. Its loop and shutdown are joined
before its cache is closed. Individual mode continues to disable SFTP.
Configuration failures return to their caller instead of calling `log.Fatal`
from agent work. The service closes its logger after runtime cleanup; new Unix
log directories include the owner execute bit required to access their files.

These changes deliberately do not claim a bounded stop for every existing
inventory tool, software/profile handler, legacy broker request, keychain call
or SFTP authorization request. Work that ignores cancellation is joined rather
than abandoned with freed resources. Remaining OS execution bounds are required
for complete native service acceptance.

## Verification

The CI workflow includes lifecycle, native service and SFTP tests alongside the
existing enrollment, signature, protected storage and broker tests:

```sh
go test -count=1 ./internal/enrollmentstore ./internal/agent \
  ./internal/packagesignature ./internal/bootstrapinstall \
  ./internal/enrollcommand ./internal/service/... ./internal/commands/sftp
go build ./...
```

Linux/macOS run the race detector; macOS uses the isolated-keychain test tag.
Unix service tests send actual SIGTERM to their own fixture subprocess during
initialization and after start, and verify cleanup and failing startup exit
codes. They never construct a real inventory agent or signal another process.
Scheduler tests observe the scheduler's actual shutdown timeout and verify that
the agent retains its identity until the blocked task finishes.

Windows handler tests cover pending/running state, startup failure, interrogation
during initialization/cleanup, cancellation during start, unsupported controls,
single cleanup and logger lifetime. Additional elevated Windows tests create
uniquely named manual-start SCM fixture services under Local System, query actual
pending/running/stopped states and failure exit codes, and remove the fixtures
after releasing their cleanup gates. These fixtures use a fake runtime; existing
DPAPI/SCM tests separately verify real protected-state access as Local System.
They do not install or start a production agent or claim physical endpoint
acceptance.

Commit `6d66ea5` passed [all three native CI jobs](https://github.com/the-luap/openuem-agent/actions/runs/34198267075),
including the real Windows SCM fixture and Unix signal subprocesses, alongside
the existing native enrollment and protected-state checks.
