# Durable Windows software reconciliation evidence

The protected software journal now retains read-only reconciliation evidence
separately from immutable installer admission and execution results. The shared
signed protocol, worker transport and individual service's observation consumer
are implemented. The [console review and history](https://github.com/the-luap/openuem-console/blob/3834fa9331f4a118504563126bb06937e1e798d9/docs/windows-software-requests.md)
now provides separately confirmed checks, immutable original-scope review links,
pending cancellation and verified outcomes. Release permits a new explicit
execution request; it never retries the original installer automatically.

Each `software-reconciliation-v1-NNNN` record atomically contains the signed
read-only authorization and exact signed observation, bound to this installation.
An interrupted read has no installer side effect; an already signed result can be
persisted after task expiry if its signing time was inside the task deadline.
Records use the existing private, immutable DPAPI publication boundary. They
contain no new executable plan or artifact. The original installer envelope,
nonce, admission boot and any execution result remain unchanged.

The journal checks the pinned authority, permanent device/organization/site scope,
historical certificate generation and retirement time, original envelope digest,
original nonce and exact admission boot. Missing original admission or legacy
admission without boot evidence cannot support a definite observation. Damaged
history is an error rather than unavailable evidence.

After the authenticated private transport returns the exact task/result digest,
`AcknowledgeSoftwareReconciliation` writes a separate immutable
`software-reconciliation-ack-v1-NNNN` record. Pending receipts are enumerated from
durable storage, independently of whether the server can still deliver the task.
Restart after expiry and certificate renewal preserve the original signed result;
a current certificate supplies a fresh submission proof. A retired journal cannot
write or return new work. Exact publication and acknowledgement retries are
idempotent, including lost durable write responses and competing journal objects.

Only an acknowledged, fully verified `observed` or `drifted` result releases the
local reservation for its exact original task. `unknown`, `waiting_for_boot` and
`unavailable` remain reserved. Server authorization for a new executable task is
still required. An orphaned acknowledgement, slot gap, wrong installation binding,
changed receipt or missing release behind a later successful task rejects history.
There are at most 4,096 reconciliation records, independently of the 4,096 installer
attempts; slots are never recycled. Exhaustion requires an authorized migration
that preserves evidence. Complete storage rollback remains outside this guarantee.

Portable tests cover all five outcomes, nonce/boot/signer binding, immutable
original receipts, offline recovery after expiry, renewal with current submission
proof, damaged restores and concurrent retries. The Windows CI requires the real
DPAPI journal lifecycle test to execute without skipping. These are owned synthetic
fixtures, not physical reboot or released package lifecycle acceptance.

## Individual service consumer

The worker's `software_reconciliation_version` is independent of executable
`software_task_version`. Only the exact supported version with a protected Windows
journal enables its consumer. The existing joined software loop serializes reads
and installations and sends pending reconciliation evidence before polling for
new work. Legacy and non-Windows configuration cannot enable this path.

A current signed task authorizes only the exact original machine detection rule.
The client compares the retained admission boot with the current native session
before any observation and reads the session again afterward. Missing original
admission, legacy boot absence or unusable/changed native evidence yields
`unavailable`; a session that does not prove a later boot yields `waiting_for_boot`
without querying package state. Read failure, cancellation or malformed helper
output yields `unknown`. A successful exact read produces `observed` or `drifted`
according to the original installation or removal expectation.

The native helper has its own ten-second bound and joins on cancellation. The
consumer additionally bounds observation by task expiry and the signing
certificate's lifetime. It stores the signed result before private WSS submission,
checks the exact returned receipt and persists acknowledgement before releasing
its in-memory copy. Shutdown joins the helper and receipt publication before
closing the protected store, signer and installation lease.

Client tests cover real private WSS, all outcome branches, exact install/removal
expectations, malformed output, failed storage/replies/acknowledgements, expired
receipt recovery without polling, and joined service cancellation. Windows CI
also requires the native MSI query helper to return a signed read-only result
without skipping. That test uses synthetic boot/command evidence and an absent
fixture product; it does not claim a physical reboot or package installation.
