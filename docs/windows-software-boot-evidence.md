# Windows software admission boot evidence

New software attempts record native boot evidence in their immutable protected
start record before the installer can begin. The service reads the evidence
again after durable admission. Missing, unsupported or changed evidence prevents
execution; it does not remove the retained attempt or authorize a retry.

`ReadBootSession` combines two observations:

- The loader boot sequence from `KUSER_SHARED_DATA.BootId`, copied from the
  read-only shared kernel page using `ReadProcessMemory` on the current process.
- The original creation value of the System process (PID 4), read from a bounded
  `NtQuerySystemInformation(SystemProcessInformation)` snapshot.

The shared page's native architecture and Windows version/build must agree with
`RtlGetVersion` and the supported AMD64/ARM64 layout. The process structure size
and offsets must match the existing `golang.org/x/sys/windows` ABI. The query
allows at most eight attempts and 4 MiB. Every record offset is bounds checked;
missing, duplicate or invalid System entries reject the snapshot. Other process
metadata is discarded and cleared. The boot sequence is read again after the
snapshot; a concurrent change rejects it.

A later session requires both a strictly greater boot sequence and a different,
valid System-process creation value. This rule does not infer a reboot from wall
clock passage, service restart, a changed registry update revision or an available
agent process lease. A boot-sequence change with the same resumed System process
is insufficient. Counter rollback/wrap and missing historical evidence remain
unresolved. The BCD boot configuration identifier is not used as a kernel-session
identifier.

This is an inference from the loader sequence and the lifetime of the original
System process. It is intended to exclude previous-session delegated installers
before a separately authorized read-only reconciliation. It neither verifies an
application nor proves successful installation, rollback or completed updates.
The signed reconciliation protocol and [protected observation
journal](windows-software-reconciliation.md) now bind later-session evidence to
the original admission. The joined individual consumer rechecks the native session
after the exact read-only observation and publishes a separate durable receipt.
The explicit console review/action still needs integration. Uncertain or
restart-required execution stays reserved until a verified definite reconciliation
is acknowledged; the original execution result remains unchanged.

## Durable format and compatibility

The storage record name remains unchanged. New admission uses start-format v2,
adding canonical boot evidence inside the DPAPI-protected immutable record.
Existing v1 records remain readable with no boot evidence. Reopening, re-enrolling
against retained security records, exact task retries and lost write responses
cannot replace the original session or upgrade a legacy record. Result records,
private task envelopes and historical certificate validation retain their
existing contract. No software wire-version change is required for this local
admission format.

The native `BootSession` type aliases the shared signed protocol's evidence type,
so local admission and remote result validation use identical comparison rules.

The service's journal interface requires `BeginWithBootSession`. The legacy
`Begin` method remains solely for retained-format compatibility and fixtures;
it is not the individual service's execution admission path.

## Verification and limits

Portable tests exercise admission-before-execution, invalid and changing native
readers, immutable restart recovery, lost write acknowledgement, canonical record
validation, legacy absence, incomplete process snapshots and conservative session
comparison. Fuzzing covers the bounded process snapshot decoder. The Windows CI
requires the native read test to pass without skipping, including a separate
owned process that must read the same session. Native DPAPI tests preserve both
old and new admission formats.

These tests neither restart nor hibernate the runner. They do not establish
physical reboot/resume acceptance, snapshot-restore recovery, protection against a
compromised local administrator or rollback of an entire protected installation.
Unsupported kernel layouts fail closed instead of falling back to wall-clock
estimates. Supported-OS and physical lifecycle acceptance remain roadmap work.

Primary references:

- [Microsoft KUSER_SHARED_DATA](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data)
- [Microsoft shared user-mode page](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-kuser)
- [Microsoft ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
- [Microsoft NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
- [Go Windows process information ABI](https://cs.opensource.google/go/x/sys/+/v0.47.0:windows/types_windows.go)
