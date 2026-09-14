# Reviewed native NetBird removal admission

The [shared removal contract](https://github.com/the-luap/openuem-nats/blob/10ed2cf2ed01f76a0f83cb825f2a6c48fb86550e/docs/netbird-removal-commands.md) now defines a source-free installed
target, a version-four `uninstall` command and a version-three read-only native
inspection. The agent journal and executor support exact admission and recovery.
No native observer or remover is configured yet, so deployed services report
inspection unavailable and reject removal before creating an attempt.

## Native owner and common exclusion

`DurableExecutor` has separate installation and removal planners. Neither can
fall through to the connection runner or select the other's owner. A native lease
retains its inspected journal revision, execution callback and joined cleanup.
New removal admission requires `Journal.BeginRemoval` with the same ready revision;
ordinary `Begin` cannot bypass that native inspection binding. Exact retained
results remain readable on replay.

The journal synchronizes the original immutable attempt before native execution.
The command deadline bounds execution and completion. Cancellation waits for the
native callback and cleanup before returning; failed execution or cleanup retains
an unconfirmed result. Another removal, installation, registration or connection
cannot cross this barrier. Same-boot orphaned native work remains unreleasable;
a later boot still needs an explicit release.

Withdrawal permanently reserves the original UUID and complete command hash without
pretending to remove anything. Original receipt queries survive certificate renewal
under the current individual identity. Native removal entries and withdrawal
records are rejected under a legacy journal anchor. A plain journal cannot supply
native ownership evidence through an inspection response.

## Verification

Owned filesystem, cancellation, cleanup and real-broker tests cover rejection of
unconfigured native work, distinct planners, exact reviewed state, durable attempt
ordering, changed journal rejection, original-result replay, renewal, crash/reboot
barriers, withdrawal and mixed-identity records. Existing NetBird preparation,
installation, connection and registration race suites pass. Agent runtime,
service and enrollment-store regressions use their owned native test facilities.
No NetBird installer, daemon or removal ran in these tests.

## Native implementation still required

The [private native filesystem inspector](netbird-removal-ownership.md) now verifies
receipt/version, protected bundle contents, publisher signatures, CLI link and
supported daemon plist ownership under stable before/after snapshots. It does not
advertise readiness or treat static files as proof of native runtime ownership.
The [combined runtime observer](netbird-removal-runtime.md) now binds actual
launchd and process identity through repeated snapshots before constructing the
shared removal state fingerprint privately. It remains unconfigured until the
native execution owner and result verification are available.
The removal planner must recheck that fingerprint and each owned object before
mutation, stop the exact service/UI processes, remove only reviewed package-owned
objects and verify absence. It must retain configuration and provider state unless
separately reviewed scope explicitly authorizes their removal. A package name,
process name, stale inventory report or arbitrary shell command is insufficient.

The official macOS package places the app under `/Applications` and adds its
daemon. The vendor documents separate service stop/uninstall commands, which need
ownership and outcome checks before use in managed removal.
[NetBird macOS installation](https://docs.netbird.io/get-started/install/macos),
[NetBird macOS troubleshooting](https://docs.netbird.io/help/troubleshooting-client/macos).
Read-only inspection of the retained official 0.78.1 ARM64 package confirms bundle
ID `io.netbird.client`, both CLI/UI executables, and the fixed `/usr/local/bin/netbird`
link. This artifact inspection is not removal acceptance.

Native owner binding, console removal requests/dispatch/recovery/UI, Linux
individual enrollment/publisher trust and actual package/daemon/device acceptance
remain required to complete the workflow.

The console, agent and worker share immutable protocol revision
`v0.11.1-0.20260914083905-10ed2cf2ed01`. The removal protocol and guarded native
admission are present; the native remover and console workflow remain required.
