# Independent current NetBird package absence

A final native query can fail after a removal has already deleted its stage.
The retained result is still unconfirmed. Without its original manifest, the
agent cannot continue the original staged removal or prove that the original
descriptor caused the current state.

The native package layer now provides a separate read-only current-absence
observer and acquired verification owner. The existing uninstall and manifest
continuation final checks use the same stricter observer. A new remote
verification protocol, journal admission and console flow are still required
before an operator can request this independent verification.

## Evidence and fixed scope

The observer covers the supported official macOS package layout: the fixed app,
CLI link, system daemon plist, both package receipt files, the native package ID,
the system job, original executable paths and the complete removal-stage
namespace in Applications. This is current evidence for that layout, not a
claim about arbitrary copied executables elsewhere on the device.

Every missing path component must return `ENOENT` through its protected parent
directory descriptor. Existing ancestry must have trusted ownership, modes and
ACLs, with no symlink traversal. Both existing and missing ancestors are retained
in the private snapshot. Open first-pass descriptors prevent inode reuse during
comparison and remain held by an acquired owner until joined close.

Two rounds each require an unloaded typed system job, a complete bounded process
scan and a successful bounded native receipt list without the exact package ID.
Each round is followed by a complete filesystem snapshot that must match the
initial one, including its ancestry. A source file, receipt, stage or replacement
directory appearing during the final native query refuses confirmation.

Process paths anywhere in the removal-stage namespace veto absence, including
after that directory was deleted and even with an unknown or malformed stage
UUID. This refusal grants no authority to signal or delete anything. The
existing process enumeration still requires a complete bounded result and
rejects inaccessible candidates.

Only a domain-separated fingerprint leaves the native observer. Private paths,
inode details and ACLs cannot be serialized or incidentally formatted. The
fingerprint binds current ancestry and the fixed absence profile; it does not
include or fabricate an original request, manifest or native descriptor.

## Acquired read-only verification

`InspectRemovalAbsence` returns the current fingerprint on supported native
services. `PrepareRemovalAbsence` obtains the same reviewed state and retains
its ancestry. Its single-use `Run` repeats the full observation and requires
the exact review and ancestry. `Close` joins execution and closes descriptors.

The owner has no mutation callback. It cannot stop a process, forget a receipt,
unlink payloads, remove a stage, rerun an old command or change a journal. A
future caller must admit a distinct verification operation and interpret success
as a new current-state observation, preserving every earlier uncertain result.
These exports are not yet configured as a remote command or capability.

## Missing and incomplete evidence policy

| Current state | Native observation policy |
| --- | --- |
| Complete original manifest and supported remaining objects | Existing explicitly reviewed manifest continuation |
| No stage, no supported payload/receipt/job/process, stable protected ancestry | Independent current absence may be observed |
| Empty original stage, including after manifest deletion | Refuse absence and preserve the stage |
| Stage with a missing, empty or incomplete manifest | Refuse absence and preserve all objects |
| Foreign or unknown stage, file or symlink in the stage namespace | Refuse absence and preserve it |
| Replacement payload, partial receipt state, loaded job or running staged process | Refuse absence |
| Unavailable, changing, cancelled or incomplete queries | Refuse absence |

There is no inferred original ownership, synthesized manifest, automatic stage
cleanup or silent fresh removal. A future empty-stage cleanup policy needs its
own explicit review and admission. Current absence never rewrites a historical
unconfirmed receipt.

## Verification

Owned filesystem tests cover full and missing ancestry, stable fingerprints,
descriptor retention, every supported remaining object, empty/missing/truncated
manifests, foreign stages, symlink/file/unsafe parents, late native query failures,
late replacement directories, new payloads/receipts/stages, cancellation and
processes from deleted stage namespaces. Owner tests preserve replacement files,
reject changed reviews and enforce single use and joined close.

The full native package, command service and journal race suites passed on macOS
(37.334, 11.064 and 10.220 seconds). The full native package suite passed in an
isolated Linux container without networking. macOS CGO, Linux and Windows agent
builds and native package test compilation on macOS without CGO passed. No test removed a host NetBird
installation or executed a vendor payload.
