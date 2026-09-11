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
The complete container table must fit both raw and virtual `.wixburn` sizes. The
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
race tests pass in 1.402 seconds, and the existing Windows software suite passes
in 26.273 seconds. The layout fuzz run passes 5,276,614 inputs in 31.649 seconds;
focused vet and the tagged Windows test compilation also pass.

The Windows CI job builds owned x86, AMD64 and ARM64 bundles using WiX and its
Bal extension, both pinned to `4.0.6`. A generated Go payload does nothing and is
never run. WiX independently extracts each generated UX manifest, and the test
compares its registration code with our PE reader's result. The compiler and its
extraction command operate only on those owned fixtures. No generated bundle,
bootstrapper application or installer payload is executed, and no certificate
is imported. The job requires every architecture case to pass without a skip.
This native fixture was added with the reader; its first CI result is pending.

Before execution integration, a bounded cabinet/registration reader must verify
the embedded manifest against the header, exact registration version, machine
scope and registry view. Appropriate authenticated plan/capability changes must
require that proof before source-derived Burn approval and delivery become
available. Package behavior, execution/recovery and physical endpoint acceptance
remain separate requirements. The full roadmap remains in progress.

The independent implementation uses format facts from Microsoft's
[PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
and the pinned WiX
[Burn section format](https://github.com/wixtoolset/wix/blob/77aa9818ad37637f961afe143be88bdc38a3f350/src/wix/WixToolset.Core.Burn/Bundles/BurnCommon.cs)
and [UX container offsets](https://github.com/wixtoolset/wix/blob/77aa9818ad37637f961afe143be88bdc38a3f350/src/burn/engine/section.cpp).
The generated-fixture test follows WiX's
[bundle authoring](https://docs.firegiant.com/wix/tools/burn/) and
[versioned extension acquisition](https://docs.firegiant.com/wix/tools/wixexe/).
