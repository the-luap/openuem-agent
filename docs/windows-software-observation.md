# Exact Windows software observations

`internal/windowssoftware` reads the machine detection rule recorded by an
approved Windows package. It is independent of installer exit status and the
general inventory's display-name merging. This is a local observation foundation;
it is not yet connected to an authenticated catalog assignment, installation
result or durable operation history.

`Observe` accepts one exact detection rule. `Observation` distinguishes `present`,
`absent` and `unknown`, preserving the exact reported version when present.
`Matches` requires that version to equal the approved rule's expected version.
A different version is still present; an inaccessible or malformed record is
unknown. Callers must bind observations to the approved device/operation and their
fresh challenge before treating them as installation or removal evidence.

## Native reads

MSI detection calls `MsiGetProductInfoExW` for the approved uppercase product GUID,
machine context (`4`) and a null user SID. It requires installed state `5`, reads
`VersionString`, then requires installed state again. An initially unknown product
is absent. Advertised state, permission errors, corrupt data, a missing version or
a product disappearing during the read remain unknown. No MSI repair,
advertisement, configuration or installation function is called.
These values and semantics follow Microsoft's
[product information API](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msigetproductinfoexw)
and [installation context definitions](https://learn.microsoft.com/en-us/windows/win32/msi/product-context).

Registration detection reads only the selected 32-bit or 64-bit HKLM view and
the exact subkey under `Software\Microsoft\Windows\CurrentVersion\Uninstall`.
It requests query access and opens a final symbolic link itself instead of
following it. Link markers are rejected. An absent key is absent; an existing key
requires a bounded, terminated `REG_SZ` `DisplayVersion`. Expandable strings,
integer values, invalid UTF-16, embedded terminators, oversized values and missing
versions remain unknown. It does not enumerate applications, inspect user hives,
read uninstall commands or execute registry content.
See Microsoft's [uninstall registration fields](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key)
and [registry opening options](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw).

## Process and input boundaries

The installed Windows executable dispatches
`--openuem-observe-windows-software` before logger, enrollment identity and service
initialization. The parent starts only that same executable, sends the canonical
rule through a private stdin pipe and receives canonical observation JSON. Neither
the rule nor diagnostics enter shell commands or ordinary application logs.
The read-only helper has no installer or broker operation.

The parent applies a ten-second deadline, honors earlier cancellation, kills and
joins the owned helper, bounds retained output to 2 KiB and limits pipe cleanup to
one second. The MSI and registry reads use fixed-size native buffers; they do not
allocate the size requested by a registry value or repeat an unbounded read.
Malformed, duplicate, unknown, case-aliased, partial and excessive messages fail.
Nonzero exits and native diagnostics return one redacted observation error.

These reads describe a point in time, not an atomic system-wide snapshot. The
future operation controller still needs serialized mutations, fresh observation
binding, reboot evidence, durable offline results and explicit recovery after a
lost execution outcome. The helper's timeout does not reverse an installation.

## Tests

Portable race tests use owned copies of the test executable for valid, absent,
different-version, oversized, incomplete, duplicate, failed and stalled output.
Cancellation requires a joined process and unknown state. MSI decision tests
exercise installed/advertised/absent/error transitions and disappearance between
state and version reads, without changing an MSI installation.

Required native Windows CI tests read a randomly generated absent MSI product and
create only uniquely named synthetic registry registrations in both machine views.
They verify view separation, exact versions, malformed data and silent rejection
of invalid helper input. Every owned key is removed. No package is installed or
removed, and no existing registration is modified. The workflow requires explicit
passing events for all three native observation tests; skips do not satisfy it.
Cross-compilation alone does not establish this native evidence.

Physical endpoint acceptance, actual install/remove integration and authenticated
delivery remain open. The [bounded installer runner](windows-package-execution.md)
and the console's approved catalog are separate prerequisites that still need to
be joined through the individual-agent package protocol.
