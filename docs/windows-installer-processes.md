# Native Windows installer processes

`deploy.RunSoftwareProcess` adapts an already approved MSI/EXE plan to the
existing suspended-process and kill-on-close Windows Job boundary. This helper
does not authenticate a task, authorize an attempt, inspect compatibility, verify
an artifact, or establish installed state. Its caller must complete those steps
and retain the protected artifact and installation service lease through execution.
The individual software client is not yet connected to this adapter.

`windowssoftware.CheckHost` uses a bounded read-only child of the installed
agent to read the native machine architecture and Windows version. Emulation is
not native package eligibility. The loaded Windows build must match the registry
build; the update revision is read twice. Registry revision is compatibility
evidence, not proof that a reboot completed. `CheckInstaller` retains and checks
the protected staged file before and after reading exact MSI product code,
reported product version and summary architecture, or the EXE's native PE
architecture. MSI database access is strictly read-only and cannot advertise,
repair or configure a product. The helper owns a ten-second deadline and returns
only a bounded canonical compatibility result over private pipes.

Primary API references: [native architecture](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2),
[read-only MSI database access](https://learn.microsoft.com/en-us/windows/win32/api/msiquery/nf-msiquery-msiopendatabasew),
[MSI template architecture](https://learn.microsoft.com/en-us/windows/win32/msi/template-summary).

EXE arguments use Windows argv quoting without a shell. MSI commands use the
system-directory `msiexec.exe`, an exact product code or absolute staged file,
quiet machine installation and suppressed reboot. Approved public properties use
the [documented MSI property-value syntax](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options).
The protocol rejects quotes, control characters and reserved engine properties.
The adapter rejects relative, UNC, noncanonical and incorrectly suffixed paths.

The process starts suspended, enters an owned job, then resumes. The explicit
inherited handle list contains only standard input/output/error. Cancellation
terminates and joins owned processes and bounded output readers. The public
result contains only whether execution started and, on completed execution, the
full unsigned 32-bit exit code. Native diagnostics and private arguments are not
returned. Independent Windows Installer or other service work can outlive a job;
interruption cannot establish rollback or completion.

Native tests launch copies of the test executable for literal argv, exit codes,
bounded output and cancellation. A separate `openuem_msi_test` build tag and
`OPENUEM_WINDOWS_MSI_FIXTURE=1` opt-in enable a generated, unsigned, registry-only
MSI on the ephemeral Windows CI runner. Each fixture has random product,
component, package and upgrade identifiers and a unique machine registry key.
It contains no files, scripts, custom actions, services or network sources.
The test installs through the adapter, reads machine MSI state and exact native
registry values, removes that product, and verifies absence. Cleanup targets
only that generated product. It tests MSI property values containing spaces,
empty strings, Unicode, literal shell characters and trailing backslashes.

The unsigned synthetic fixture enters the low-level process adapter directly.
It cannot bypass production staging or signature verification because it does
not invoke either. Separate staging tests exercise actual Authenticode with an
existing signed fixture without executing it. These are CI tests, not acceptance
on an enrolled Windows device or proof of the complete task delivery lifecycle.
