# Read-only Burn layout inspection

`internal/burnbundle.Inspect` locates the UX cabinet and section-declared bundle
code in a version-2 `.wixburn` PE image. This is a metadata-reading foundation;
it is not called by the installer executor and does not enable Burn delivery.
The existing native EXE preflight still checks native PE architecture, while
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
subsequent native callbacks. The existing preflight subprocess must supply the
hard process deadline when this reader is integrated into execution.

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
Windows runner; native ARM64 process and physical endpoint acceptance remain open.

The decoder uses the explicit `-1` notification result to stop after complete
manifest output. FDI reports this as `FDIERROR_USER_ABORT`; returning `FALSE` from
the close notification instead reports a target-file error. Success requires the
explicit abort, complete expected bytes, unchanged cancellation state and closed
native resources. Ordinary I/O errors and partial output never become identity
evidence. Internal tests can inspect bounded counters/status codes; those
diagnostics contain no member data, names or native addresses and are not exposed
by the public reader.

Before source-derived Burn delivery, authenticated plan/capability changes and
the preflight helper must require this proof and compare it with the exact
approved machine registration. Source approval/provenance, package behavior,
execution/recovery and physical endpoint acceptance remain separate requirements.
The full roadmap remains in progress.

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
