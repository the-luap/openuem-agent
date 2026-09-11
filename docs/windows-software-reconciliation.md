# Durable Windows software reconciliation evidence

The protected software journal now retains read-only reconciliation evidence
separately from immutable installer admission and execution results. The shared
signed protocol and worker transport are implemented. Connecting the individual
service's observation consumer and the explicit console action remains in progress;
this journal does not itself poll, observe software or start an installer.

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
