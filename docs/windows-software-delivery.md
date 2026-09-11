# Windows software delivery and durable receipts

The software client verifies the command signature against the independently
pinned enrollment CA, decrypts the exact current-generation plan, and records a
durable attempt before calling its native executor. The individual Windows service
now connects the protected recipient/journal, exact server capability and native
MSI/EXE adapter through one joined consumer. Existing console preparations do not
start installers. The console now has a [separate explicit dispatch and verified
result history](https://github.com/the-luap/openuem-console/blob/3834fa9331f4a118504563126bb06937e1e798d9/docs/windows-software-requests.md).
The individual read-only reconciliation consumer and durable evidence are now
implemented, alongside separate console review, confirmation, cancellation and
verified reconciliation history.

[Protected installer staging](windows-installer-staging.md) now implements the
separate HTTPS, hash, private-file and native-signature boundary.
[Native installer execution](windows-installer-processes.md) adds bounded read-only
host/package preflight, exact before/after observations, owned processes and
conservative success/reboot/failure/interruption outcomes.

The protected journal uses immutable numbered start/result records. Native
Windows storage uses DPAPI and System/Administrator-only publication. A start
record contains the signed encrypted envelope, response nonce and
[immutable native boot evidence](windows-software-boot-evidence.md), never plaintext
artifact URLs, installer arguments or MSI properties. Only the exclusive durable
creator can admit execution. Lost publication acknowledgements, existing attempts,
corrupt records, gaps and partial restores cannot authorize another attempt.
The journal retains at most 4,096 attempts and never recycles a slot. Exhaustion
requires an authorized migration preserving replay history; it cannot reset itself.

The software X25519 recipient is separate from FileVault and changes for every
committed certificate generation. Historical keys/receipts are not overwritten.
The journal validates original certificate history and retirement time while
requiring the currently selected generation for new work and newly signed results.
Results survive task expiry and identity renewal and are submitted with a fresh
current-certificate proof. Deleting or rolling back an entire protected installation
is outside the journal's crash-recovery guarantee; recovery must preserve its
identity and complete immutable history.

After a crash, a retained attempt without a result yields `uncertain` execution.
An orphaned installer or Windows service might still be working. Neither a free
agent process lease nor elapsed time proves termination or rollback. The server
keeps uncertain/restart-required work reserved. New attempts now retain native
boot evidence before execution; legacy attempts cannot acquire it retroactively.
The [signed reconciliation journal](windows-software-reconciliation.md) now retains
separate observations and acknowledgements, recovering pending evidence after
task expiry and renewal. Only a verified acknowledged definite observation can
release the exact local reservation. The joined individual observation consumer
uses the original detection rule after later-boot verification. A separately
confirmed console check authorizes that read; release does not retry the original
installer or queue a replacement execution automatically.

The client owns one cycle at a time under the installation service lease. It
limits RPCs to five seconds, bounds native work by task expiry and leaves thirty
seconds before certificate expiry for signing. It stores the exact signed result
before any transmission, retains it across failed replies, and checks the returned
task/result digest. Cancellation still attempts durable result publication before
joined shutdown. Raw native diagnostics never form a software result.

Verification includes competing Store/journal instances, lost intent/result commit
responses, corrupt/foreign/partial records, generation-specific recipients,
historical results after renewal, and private WSS receipt retries. Native DPAPI
journal coverage is part of the Windows test suite. Joined service tests exercise
private WSS delivery and cancellation with a controlled executor, including signed
receipt persistence before key release. Separately opted-in native fixtures create,
install, observe and remove only uniquely identified synthetic MSI products on the
ephemeral CI runner. They are not physical endpoint acceptance or a released,
signed package lifecycle through the full console/worker/agent installation.
