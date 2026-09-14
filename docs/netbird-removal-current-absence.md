# Independent current NetBird package absence

A final native query can fail after a removal has already deleted its stage.
The retained result is still unconfirmed. Without its original manifest, the
agent cannot continue the original staged removal or prove that the original
descriptor caused the current state.

The native package layer now provides a separate read-only current-absence
observer and acquired verification owner. The existing uninstall and manifest
continuation final checks use the same stricter observer. The agent now joins
the separate remote verification protocol and journal admission described below.
The [scoped console request, delivery, resolution and user interface](https://github.com/the-luap/openuem-console/blob/f7f16022281a755b3177fc7a15ceb364d493d8cf/docs/netbird-removal-absence.md) are integrated.

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
caller admits a distinct verification operation and interprets success
as a new current-state observation, preserving every earlier uncertain result.
Supported individual native services now configure these exports as the paired
observer and acquired owner for the separate verification protocol below.

## Remote verification and permanent journal evidence

Shared command version six, `verify-removal-absence`, and inspection version five,
`removal-absence-state`, use the explicit `macos-official-pkg-v1` profile. An
original reference contains only the uninstall UUID, command hash, console
revision and owned release UUID. No original package descriptor is inferred
from current absence. Commands expire within two minutes; inspections within
45 seconds. Every request requires the exact current individual certificate.

`RemovalAbsenceState` validates the original released unconfirmed uninstall and
the current shared ready journal under its mutex. Expensive native inspection
and acquisition are each bracketed by the same proof. A changed journal, current
identity, deadline or native fingerprint discards the review. The service only
advertises this inspection when both the observer and acquired owner are present.
A bare journal returns unavailable for every native inspection kind.

`BeginRemovalAbsence` admits the separate immutable attempt only against the
exact ready-journal revision from acquisition. Generic, installation, removal
and manifest-continuation admission cannot start this verification. It shares
the common device barrier and permanent request UUIDs with every other operation.
Concurrent verification and mutating continuation cannot both acquire the same
reviewed journal state.

The dedicated executor path runs only the read-only owner and joins its close
before recording completed or unconfirmed. Failure and cancellation retain the
new uncertainty and barrier. Original released proof cannot bypass that later
barrier. A crash still requires later boot evidence and explicit release before
a fresh review can proceed. Current certificate renewal preserves the original
historical proof but changes the current review revision.

Exact replay and permanent withdrawal are read before native acquisition, even
after expiry. They never call a connection, installation, removal or manifest
continuation runner. The original uncertain receipt and release remain identical
after success, restart, replay and later verification. Completed means only that
the new verification confirmed current absence of the fixed supported layout.

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
cleanup or silent fresh removal. The separate [native scaffold cleanup](netbird-removal-stage-cleanup.md)
now supports an explicitly reviewed current scope, with its own acquired owner.
Its remote admission and console lifecycle remain open; the read-only observer
never invokes it. Current absence never rewrites a historical unconfirmed receipt.

## Verification

Owned filesystem tests cover full and missing ancestry, stable fingerprints,
descriptor retention, every supported remaining object, empty/missing/truncated
manifests, foreign stages, symlink/file/unsafe parents, late native query failures,
late replacement directories, new payloads/receipts/stages, cancellation and
processes from deleted stage namespaces. Owner tests preserve replacement files,
reject changed reviews and enforce single use and joined close.

The original native package, command service and journal race suites passed on macOS
(37.334, 11.064 and 10.220 seconds). The full native package suite passed in an
isolated Linux container without networking. macOS CGO, Linux and Windows agent
builds and native package test compilation on macOS without CGO passed. No test removed a host NetBird
installation or executed a vendor payload.

The subsequent protocol integration passed the full macOS native package,
journal and command service race suites (37.074, 10.567 and 12.625 seconds).
Full journal and command suites passed in isolated Linux containers without
networking. macOS CGO, Linux and Windows agent builds passed. Owned broker tests
verify separate current-state receipts, one acquired owner, exact replay without
inspection, stale proofs, capability separation, cancellation joining and
unchanged original results. Journal tests cover restart, renewal, withdrawal,
current-revision concurrency and common exclusion with manifest continuation.
