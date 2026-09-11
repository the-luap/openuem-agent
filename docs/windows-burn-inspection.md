# Read-only Burn inspection and bounded preflight

`internal/burnbundle.Inspect` locates the UX cabinet and section-declared bundle
code in a version-2 `.wixburn` PE image. Together with `ReadRegistration`, it now
supplies the bounded helper for explicit Burn plans. New execution requires
both the private profile hint and a matching device-signed recipient capability.
The generic EXE preflight checks native PE architecture, while
protected staging separately enforces the approved digest and Authenticode policy.

The parser accepts standard PE32 x86 and PE32+ AMD64/ARM64 headers. Its returned
architecture describes the bootstrapper, not its payloads or permission to use
emulation. It preserves GUID byte order and returns a canonical uppercase braced
bundle code. Missing, duplicate, unsupported and truncated sections fail with a
fixed error and no partial metadata.

All reads use a caller-owned stable `io.ReaderAt` and a trusted file length. The
caller must retain the same protected file throughout inspection and later use.
The parser accepts at most 8 GiB of declared file length, a 1 MiB PE-header range,
96 sections, 64 container declarations and a 64 MiB UX cabinet. These independent
format limits do not increase the existing 512 MiB installer staging limit.
At most seven reads and 4,512 requested bytes locate the cabinet; declared sizes
never allocate a whole image, section or cabinet. COFF symbol tables, payloads,
certificate bodies and CAB members are not followed.

File and virtual section ranges must be aligned, complete and non-overlapping.
The fixed prefix must fit the declared virtual section, while the appended
container table must fit the raw `.wixburn` bytes. WiX declares a 48-byte virtual
prefix even when the appended table extends beyond it. The
UX cabinet begins after all PE sections, fits the file, and declares the same
cabinet length. Current and retained original certificate ranges must fit the
file and cannot overlap the UX cabinet or PE sections. Two certificate ranges
may be identical but cannot partially overlap. These are structural checks, not
signature verification. Additional attached payload declarations are bounded but
their contents and presence are not verified by this reader.

Portable tests cover all three bootstrapper architectures, GUID endianness,
unsigned and certificate-range variants, attached/detached declarations, section
ambiguity, arithmetic bounds, every fixture truncation and each read failure.
An instrumented reader checks read count, byte count and access bounds. Local
race tests pass in 1.415 seconds, and the existing Windows software suite passes
in 26.273 seconds. The initial layout fuzz run passes 5,276,614 inputs in 31.649 seconds. The
corrected 48-byte-prefix reader passes another 151,135 inputs in 16.610 seconds;
focused vet, the full Linux ARM64 build and tagged Windows test compilation also
pass.

The Windows CI job builds owned x86, AMD64 and ARM64 bundles using WiX and its
Bal extension, both pinned to `4.0.6`. A generated Go payload does nothing and is
never run. WiX independently extracts each generated UX manifest, and the test
compares its registration code with our PE reader's result. The compiler and its
extraction command operate only on those owned fixtures. No generated bundle,
bootstrapper application or installer payload is executed, and no certificate
is imported. The job requires every architecture case to pass without a skip.
All three generated architectures pass in the native Windows fixture at agent
commit `383c6fd1d1e31564ede725eac00317d94423959f`. The independent manifest
comparison uses WiX 4's `Registration/@Id`; newer authoring uses `Code`. This
version distinction must be preserved by the future production manifest reader.

## Embedded registration reader

`ReadRegistration` now reads the bounded UX directory, decodes only its manifest
into memory and binds the embedded registration to the section-declared bundle
code. The result contains bootstrapper architecture, exact displayed version,
fixed machine/user scope and the corresponding 32/64-bit registry view. Flexible
scope cannot establish a fixed registry hive and is rejected. Header architecture
and the manifest's `Win64` declaration must agree. The reader supports the known
`Id`/`PerMachine` and `Code`/`Scope` attribute shapes without mixing them.

Directory inspection checks every file entry and compressed-block range. It
limits metadata to 1 MiB, files to 4,096, folders to 64, data blocks to 65,536,
the manifest to 1 MiB and declared expanded UX data to 512 MiB. Names remain
bounded opaque member identifiers; path components, duplicate names, spanning
cabinets, execute attributes, overlapping files/blocks and unsupported compression
are rejected. The manifest must be the unique first member `0`, starting at the
beginning of the first folder. Reserved CAB header/folder/block areas are bounded.

On native AMD64/ARM64 Windows processes, the fixed system `cabinet.dll` FDI API
handles uncompressed, MSZIP and LZX data. All file callbacks use memory-backed
handles; archive names never become filesystem paths. Only the manifest receives
an output handle, and decoding deliberately stops when its exact output completes.
No archive file or payload is written or executed. A single invocation gate and
once-registered callbacks bind native work to its current reader without leaking
callback registrations across requests. Native allocations are limited to 16 MiB
per allocation, 32 MiB simultaneously and 64 MiB cumulatively; input reads are
limited to 128 MiB. Native context, allocations and virtual handles must close
before successful output is returned. Cancellation rejects waiting admission and
subsequent native callbacks. The preflight subprocess now supplies a hard process
deadline for this reader, independently of cooperative callback cancellation.

The XML reader limits document size, depth, tokens and attributes and rejects
directives, external entities, duplicate attributes, repeated/nested registration
identities, unknown registration behavior, mixed schemas and mismatched displayed
versions. Only the selected identity fields leave the reader; manifest contents,
archive names and native error details are not returned as errors.

Portable tests cover multiple folders, reserved data, MSZIP block history,
directory/expansion bounds, scope/bitness, schema ambiguity, truncation and read
failures. The CAB and XML fuzz runs pass 3,412,453 and 629,931 inputs in
20.528/21.283 seconds. The final local race suite passes in 1.588 seconds, and tagged Windows
AMD64/ARM64 compilation passes. Native Windows race tests pass in 1.472 seconds,
including memory-only decoding, read/codec failures, cancelled admission and
concurrent reuse. The complete registration reader passes against all three
generated WiX architectures in 15.10 seconds, including rejection of a changed PE
bundle code. All Linux, macOS, Windows and generated-format CI jobs pass at agent
commit `bf1f80adf9960387f82e414d60263b7054816c23`. These runtime checks use an AMD64
Windows runner; subsequent native ARM64 evidence is recorded below. Physical
endpoint acceptance remains open.

The decoder uses the explicit `-1` notification result to stop after complete
manifest output. FDI reports this as `FDIERROR_USER_ABORT`; returning `FALSE` from
the close notification instead reports a target-file error. Success requires the
explicit abort, complete expected bytes, unchanged cancellation state and closed
native resources. Ordinary I/O errors and partial output never become identity
evidence. Internal tests can inspect bounded counters/status codes; those
diagnostics contain no member data, names or native addresses and are not exposed
by the public reader.

## Bounded preflight and explicit capability

The pinned shared protocol now distinguishes `windows-burn` from a generic EXE
in the canonical signed plan and requires a capability retained from the device's
signed recipient registration. Existing MSI/EXE wire encodings remain unchanged.
`CheckInstaller` maps only that explicit kind to the private `burn` helper request;
an EXE extension or GUID-shaped uninstall key never selects Burn implicitly.
The helper requires native AMD64/ARM64 host compatibility and matches the complete
embedded bundle code, exact displayed version, fixed machine scope and 64-bit
registry view against the approved detection rule. It reopens only the protected
retained stage with write/delete sharing excluded, and the parent verifies the
same stage and its approved digest before and after inspection. Both install and
remove inspect the pinned EXE; no mutable uninstall command is read.

The ten-second parent cancellation and child exit timer bound native FDI work.
Only a canonical positive response after complete proof is accepted; helper
diagnostics are discarded. Portable pinned-module race tests pass for Windows
software, Burn readers and agent admission in 26.115/1.882/20.023 seconds. Tagged
Windows AMD64/ARM64 compilation and focused Windows vet pass. The generated native
fixture now additionally exercises the real helper on native machine/user,
foreign-architecture and x86 bundles, plus wrong identity/version/digest, retained
stage closure, cancellation and removal. All four native helper cases pass in
13.58 seconds at `767bf1a9ec62456807bc783c2cd60db9dbc6f30e`; the generated layout
suite also passes in 15.44 seconds with race detection. Linux and macOS CI pass.
The separate Windows storage suite failed during isolated broker provisioning
and cleanup. Its package processes now run serially after parallel compilation
to reduce shared runner disk/CPU contention. The complete native Windows suite
passes at `68876c30fd6301327b5d3f2e45c82a54c5ce0311`. A per-package test timeout
preserves diagnostic stacks if an intermittent hang returns; production
timeouts and assertions remain unchanged.

The agent requests Burn version 1 only when a successful private server profile
advertises that exact version alongside Windows software support and a protected
native AMD64/ARM64 identity. The challenge, device signature and returned recipient
must retain the requested version. A profile change is checked before signing,
after registration, before durable admission and before native execution. The
live native boundary checks permission again during staging and before starting.
The process builder maps the explicit Burn kind to its retained EXE and fixed
quiet arguments for both operations; unsupported kinds cannot fall through to MSI.

Changes in profile capability renegotiate the recipient before another poll.
Pending signed outcomes are persisted and delivered before renegotiation;
historical journal recovery and later-boot observation do not require new Burn
admission. Old profiles omit the hint and retain version zero. Mismatched server
replies cannot introduce support. Focused portable race tests cover upgrade,
downgrade, withdrawn/mismatched grants, withdrawal before/after durable admission,
unchanged lost-receipt retries and protected platform gating in 8.521 seconds.
Source approval/provenance integration and physical endpoint acceptance remain
outstanding.
The full roadmap remains in progress.

## Owned execution fixture

A separate Windows CI job now builds a uniquely identified Burn bundle containing
only the existing generated registry-only MSI fixture. It checks actual bundle
and MSI installation, the already-installed no-op, refusal to remove a different
version, fetching the same pinned bundle for removal, native absence and stage
cleanup. The generated MSI has no files, scripts, custom actions or services.
Both the MSI product and bundle upgrade identities are unique to the owned test.
The fixture has an explicit environment opt-in and must pass without skipping.

Only this test seam accepts the generated unsigned artifact. It uses the real
Burn preflight and direct process builder. Production execution still requires
an approved signed plan and the negotiated capability. The first native run exposed WiX's
unconditional file-size query while binding the registry-only MSI. The fixture
now includes the standard empty [File table](https://learn.microsoft.com/en-us/windows/win32/msi/file-table)
without adding any installed files. The complete native installation/removal
fixture passes with race detection in 20.73 seconds at
`f3f1325798db896357e973f0b684633f68d19300`.

A second generated bundle carries only a waiting process and its child. It
checks cancellation and an installer that exits while its child remains alive
with closed output. The fixture retains process handles only after verifying
the unique generated executable's digest, requires joined termination and an
uncertain outcome without an exit code, and removes its own bundle registration.
The native lifecycle fixture passes with race detection at
`e8d0e91856d41aeb8263eba81c51fa3a73f82d48`: cancellation in 11.91 seconds and the
unfinished child in 10.59 seconds, alongside installation/removal in 20.30 seconds.
Those runs used the generic EXE process seam. The explicit Burn command branch
now passes the same native race fixtures at
`39eb6c94d3436f00a24069dc2572be003284910f`: installation/removal in 21.26 seconds,
cancellation in 12.88 seconds and the unfinished child in 11.27 seconds. The
subsequent native execution job also passes at
`589bf1b7e872984896307ccd185d57601c49b0b5`.

Portable agent race tests additionally preserve an interrupted historical Burn
attempt, retry a lost receipt without execution, retain a signed restart result
byte-for-byte, and check exact install/removal expectations only after a later
boot. The six reconciliation scenarios include drift, unknown observation and
same-boot waiting. These protocol fixtures pass in 4.066 seconds; they do not
represent a physical reboot or endpoint acceptance.

A separate native ARM64 job now uses GitHub's documented
[`windows-11-arm` runner](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
It requires an ARM64 Go toolchain and executes bounded CAB callbacks, all generated
format/preflight cases, actual owned Burn installation/removal and child lifetime,
plus private readiness shutdown. The generated MSI uses the native
[`Arm64` template summary](https://learn.microsoft.com/en-us/windows/win32/msi/template-summary),
and both the bundle and owned process payload use the same native architecture.
Go 1.26.8 supports its Windows race detector only on AMD64; that existing required
job retains race detection, while the ARM64 job runs native assertions without
it. ARM64 tagged compilation and vet pass.

The default-restore fixture installed its MSI successfully, but retained an
uncertain result because `SrTasks.exe` and `conhost.exe` remained in the owned job
after both output streams drained. A fixture-only diagnostic uses an aligned
native process list to identify owned job members without exposing arguments or
output; release builds do not include this entry point.

The owned execution fixtures explicitly set the authored
[`Chain.DisableSystemRestore`](https://docs.firegiant.com/wix/schema/wxs/chain/)
option so their bootstrapper does not request host restore points in addition to
the intended synthetic payload. This changes only generated bundles. Approved
plans, process timeouts, child joining and production arguments are unchanged.
Bundles that leave child work active continue to report uncertainty.

All seven jobs pass at `a1096ed17e13691f8784c4a1b788cd2398a0fc84`
([CI run](https://github.com/the-luap/openuem-agent/actions/runs/34628087765)).
Native ARM64 installation/removal passes in 7.66 seconds, cancellation in 6.81
seconds and the deliberately unfinished child in 6.66 seconds. All three generated
layouts pass in 22.60 seconds and native preflight in 9.06 seconds. Private
readiness passes its 96 shutdown cycles in 0.41 seconds alongside identity, PID,
permission, borrowed-signer and crash recovery checks. The AMD64 race jobs and
full Windows storage/LocalSystem service integration also pass. These are owned
CI fixtures, not physical endpoint or provider acceptance.

The independent implementation uses format facts from Microsoft's
[PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
and the pinned WiX
[Burn section format](https://github.com/wixtoolset/wix/blob/77aa9818ad37637f961afe143be88bdc38a3f350/src/wix/WixToolset.Core.Burn/Bundles/BurnCommon.cs)
and [UX container offsets](https://github.com/wixtoolset/wix/blob/77aa9818ad37637f961afe143be88bdc38a3f350/src/burn/engine/section.cpp).
The generated-fixture test follows WiX's
[bundle authoring](https://docs.firegiant.com/wix/tools/burn/) and
[versioned extension acquisition](https://docs.firegiant.com/wix/tools/wixexe/).
The directory and native decoder follow Microsoft's
[CAB specification](https://download.microsoft.com/download/4/D/A/4DA14F27-B4EF-4170-A6E6-5B1EF85B1BAA/%5BMS-CAB%5D.pdf),
[FDICreate](https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fdicreate),
[FDICopy](https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fdicopy)
and [notification contract](https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fnfdinotify).
The identity shapes follow the pinned
[WiX 4 writer](https://github.com/wixtoolset/wix/blob/v4.0.6/src/wix/WixToolset.Core.Burn/Bundles/CreateBurnManifestCommand.cs)
and [current writer](https://github.com/wixtoolset/wix/blob/77aa9818ad37637f961afe143be88bdc38a3f350/src/wix/WixToolset.Core.Burn/Bundles/CreateBurnManifestCommand.cs).
