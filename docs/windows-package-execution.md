# Windows package command execution

The legacy Windows install, update and uninstall commands now invoke WinGet
directly with separate arguments. They no longer interpolate package identifiers
or versions into PowerShell or infer the WinGet exit status from a shell pipeline.
This hardens the existing execution foundation; it does not complete the approved
standard/custom software catalog or establish installed-state detection. The
separate [exact Windows observation helper](windows-software-observation.md)
now reads approved machine detection rules; authenticated operation integration
and fresh result binding remain required.

## Command boundary

Requests select one exact package identifier from the fixed `winget` source,
machine scope, silent execution and disabled interactivity. An optional version
is passed as one argument. Removal selects that version when supplied and all
versions otherwise. There are no request-controlled executable paths, sources,
extra switches, shell programs, hash bypasses or reboot flags.

Identifiers and versions are checked against the relevant manifest character
and length constraints, with additional rejection of leading option markers,
controls and ambiguous surrounding whitespace. Shell punctuation that is valid
manifest data remains a literal argument. The executable locator inspects only
direct matching Desktop App Installer directories under the Windows Program
Files known folder, matches the agent's x64/ARM64 architecture, compares four-part
versions numerically and rejects package/executable symlinks. It does not search
PATH or recursively walk unrelated Windows applications. This relies on the
operating system protecting its application directory; it is not a new binary
signature or filesystem authorization verifier.

These switches are described in Microsoft's [install](https://learn.microsoft.com/en-us/windows/package-manager/winget/install),
[upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade)
and [uninstall](https://learn.microsoft.com/en-us/windows/package-manager/winget/uninstall)
documentation. Manifest grammar is defined by the
[WinGet version schema](https://github.com/microsoft/winget-cli/blob/master/schemas/JSON/manifests/v1.12.0/manifest.version.1.12.0.json).

## Lifetime and results

Managed WinGet mutations are serialized within the agent process. Their
30-minute deadline includes waiting for that execution slot. Windows profile
tasks and direct package callbacks also inherit the agent's service context.
Compatibility callers such as NetBird retain the same finite execution deadline.

Windows package profile fields are type-checked before execution. Missing required
identifiers, non-string versions, non-boolean update flags, a foreign source,
conflicting pinned/latest intent, nil resources and missing task control return
errors. Shared profile field readers also reject incorrect types instead of
panicking. This input validation does not add cancellation or command escaping to
the separate inherited MSI, registry, account or PowerShell executors.

The native runner creates the process suspended, assigns it to a private
kill-on-close Windows job and only then resumes its primary thread. Only the
three explicit standard-stream handles are inherited from the agent. It retains
at most 64 KiB per output stream while continuing to drain output. Normal process
exit also requires drained pipes and no active job children within two seconds.
Cancellation terminates the owned job, closes and joins readers, and checks job
termination for up to two seconds. It never terminates processes by executable
name. Windows callbacks close admission and join execution/result handling before
the service releases its connection. Legacy broker requests inherit service
cancellation, including the result acknowledgement wait.

Windows [process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
and [job objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
define these process boundaries. Work handed to independent Windows services can
outlive the command's job; interruption does not undo installation steps.

Every nonzero process exit is a failure with its original unsigned hexadecimal
exit code. In particular, `0x8A15002B` (no applicable update) and `0x8A150014`
(no application found) are not converted into verified success. Missing
executables, startup failures, timeouts, cancellation and unfinished child work
produce nonempty failures. A clean zero exit describes command completion only.
Stderr warnings on a zero exit are retained as output rather than independently
changing its result. The [WinGet error definitions](https://github.com/microsoft/winget-cli/blob/master/src/AppInstallerSharedLib/Public/AppInstallerErrors.h)
define the native codes.

The common legacy subscription decoder bounds requests to 8 KiB, rejects duplicate
or noncanonical fields and trailing data, and binds the payload's device and
operation to the subscribed subject. Result flags, text and timestamps are
produced locally. Install, update and removal failures all reach result reporting
and the existing pending-ack fallback; removal failures no longer set
`Failed=false`. Individually enrolled agents remain excluded from these legacy
subjects. Their approved package protocol requires separate work.

## Evidence and remaining work

Portable race tests cover exact arguments, rejected input, numeric executable
selection, output limits, cancelled slot admission, nonzero/uncertain outcomes,
request binding and every operation's success/failure reporting. An owned local
NATS server verifies interruption of an in-flight acknowledgement request.

Required native Windows CI fixtures launch only copies of the test executable.
They check exact arguments, full exit codes, large output, startup rejection,
cancelled parent/child termination, preservation of an unrelated fixture process,
unfinished children that closed their output, and service shutdown joining result
handling. A separate owner-crash fixture bypasses runner cleanup and verifies
that Windows closes the private job and terminates both owned descendants.
Argument round trips include a supplementary Unicode character. The workflow
requires explicit passing events for these native tests;
a skipped test does not satisfy the check. Cross-compilation alone is not native
execution evidence.

Actual WinGet package installation/removal on supported Windows versions,
integration of independent post-install detection, reboot requirements, restart recovery,
durable command admission and idempotent retries remain open. The inherited
pending-ack JSON file is not a transactional outbox or a crash recovery guarantee.
The legacy list helper, custom MSI/PowerShell tasks, and Brew/Flatpak process
lifetime handling are outside this execution change. No physical or enrolled
endpoint is used by these tests.

Commit `62561fb` passed
[all three native CI jobs](https://github.com/the-luap/openuem-agent/actions/runs/34566688069),
including all six required Windows execution/shutdown tests, the owner-crash
fixture and supplementary Unicode arguments. Profile input validation has
additional portable tests and a required native pre-execution rejection fixture
in the same workflow.
