# Windows software compatibility and test coverage

The individual software executor admits native AMD64 and ARM64 packages on a
matching native Windows agent. Approval, host compatibility and installation
evidence remain separate checks. The catalog's minimum Windows version is a
numeric kernel version; it does not identify a Windows edition or prove that a
package vendor supports that edition.

## Enforced admission rules

| Requirement | Current behavior |
| --- | --- |
| Host architecture | The running agent, `IsWow64Process2` native machine and approved package must match: `amd64` or `arm64`. Emulated agents and x86 packages cannot use this executor. |
| Windows version | The native kernel must report `10.0`; its loaded build must match `CurrentBuildNumber`. `UBR` must be a stable DWORD. The resulting version must meet the approved minimum. |
| Edition | This executor does not read or authorize by edition. Windows client and Server require their own package and deployment acceptance. |
| MSI | Exact native summary architecture, product code and product version; machine installation with approved public properties. Removal uses only the approved product identity. |
| EXE | Exact native executable PE architecture and fixed approved arguments; explicit machine registry detection in the approved view. |
| Burn | Explicit source-approved kind, current signed recipient support and native machine bundle registration: architecture, bundle code, exact version and 64-bit registry view. Install/remove use the same pinned artifact. |
| Artifact | Approved HTTPS source and SHA-256, private retained file and Authenticode, followed by a final integrity and live-authority check before execution. |
| Result | A completed process alone is insufficient. The exact before/after observations, exit code and cancellation state determine the recorded outcome. |

The implementation is in [native preflight](../internal/windowssoftware/preflight_windows.go),
[staging](windows-installer-staging.md), [observation](windows-software-observation.md)
and [execution](windows-installer-processes.md). A higher catalog minimum narrows
eligibility; it cannot bypass any other admission rule.

## Native CI evidence

These are disposable runner environments observed in CI, not an assertion of
physical device, every-edition or vendor-package acceptance.

| Observed OS and edition | Native architecture | Evidence |
| --- | --- | --- |
| Windows Server 2025 Datacenter, kernel `10.0.26100` | AMD64 | Owned MSI install/properties/remove and major upgrade; repeated Burn install/remove and cancellation; native file ownership, bounded cleanup, Authenticode and process checks. |
| Windows 11 Enterprise, kernel `10.0.26200` | ARM64 | The same owned MSI lifecycle, repeated Burn execution and bounded cleanup, plus native compatibility and private readiness. |

MSI replacement passes on [both architectures at `9f2a102`](windows-software-delivery.md#owned-major-upgrade-fixture).
The staging fix and repeated Burn checks pass on
[AMD64](https://github.com/the-luap/openuem-agent/actions/runs/34633746056/job/103376552064)
and [ARM64](https://github.com/the-luap/openuem-agent/actions/runs/34633746056/job/103376552000)
at `9f2a102`; all seven agent CI jobs pass.

Windows 10, Windows 11 on AMD64, other client editions and earlier Windows Server
releases are not covered by this native execution matrix. Meeting the host check
alone does not establish their acceptance. This matrix concerns agent software
delivery; native Windows MDM enrollment, edition-specific CSP policies and
Entra/Autopilot have separate requirements. Released signed installers, physical
offline/restart/hibernate behavior and the complete enrolled-device lifecycle
remain outstanding acceptance work.
