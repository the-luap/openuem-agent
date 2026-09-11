# Windows software delivery and durable receipts

The software client verifies the command signature against the independently
pinned enrollment CA, decrypts the exact current-generation plan, and records a
durable attempt before calling its native executor. The client is implemented and
tested through private WSS subjects, but is not yet wired into service startup or
the native MSI/EXE adapter. Existing console preparations do not start installers.

The protected journal uses immutable numbered start/result records. Native
Windows storage uses DPAPI and System/Administrator-only publication. A start
record contains the signed encrypted envelope and response nonce, never plaintext
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
keeps uncertain/restart-required work reserved. Explicit reconciliation and
native reboot evidence remain to be implemented.

The client owns one cycle at a time under the installation service lease. It
limits RPCs to five seconds, bounds native work by task expiry and leaves thirty
seconds before certificate expiry for signing. It stores the exact signed result
before any transmission, retains it across failed replies, and checks the returned
task/result digest. Cancellation still attempts durable result publication before
joined shutdown. Raw native diagnostics never form a software result.

Verification includes competing Store/journal instances, lost intent/result commit
responses, corrupt/foreign/partial records, generation-specific recipients,
historical results after renewal, and private WSS receipt retries. Native DPAPI
journal coverage is part of the Windows test suite. Native package execution and
physical endpoint acceptance must not be inferred from injected executor tests.
