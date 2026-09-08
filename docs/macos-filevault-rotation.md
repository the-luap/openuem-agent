# FileVault rotation journal

`internal/enrollmentstore` implements protected replay evidence for FileVault
rotation protocol v1. This component does not execute a FileVault command, start
a rotation poll loop or advertise rotation capability. The OS driver, runtime
wiring, worker routing and console escrow integration remain required
before enabling the operation. Existing read-only validation is unchanged.

## Durable records

`Store.OpenRotationJournal` verifies the already committed Mac identity and binds
`rotation-anchor-v1` to its exact pending-record digest, origin, device ID and
organization/site. It preserves existing pending, identity and recipient records.
A missing anchor with surviving attempts fails closed. An orphan anchor prevents
the installation from being mistaken for an empty enrollment store.

For each ordinal from 1 through 128, only these record names are accepted:

```text
rotation-start-v1-NNN
rotation-result-v1-NNN
```

The start record contains the installation binding, complete rotation context,
32-byte nonce and SHA-256 digest of the exact encrypted task. It contains no PRK.
The result record contains the binding and the certificate-signed outcome with
any new key encrypted to the separate console return recipient. Records are
immutable and never garbage-collected or reused. The server registry imposes the
same permanent attempt limit, including cancelled or unsuccessful attempts.

The native backend protects records with the existing System keychain boundary
on macOS. Record-name validation also applies to the Windows backend; this does
not enable FileVault execution on Windows. Owned backend plaintext is cleared
after decoding. Returned entries contain only public context, nonce, task digest
and encrypted signed receipt, and refuse accidental JSON serialization.

## Caller contract

1. Keep the `Store` open until journal users have stopped. Load the protected
   identity, obtain the active recipient epoch and authenticate/decrypt a task
   before supplying its nonce to the journal.
2. Call `macsecurity.AcquireFileVaultLease` for the same private enrollment
   directory and hold its exclusive OS lease throughout mutation and recovery.
   Immutable admission prevents duplicate execution, but an intent-only reader
   must not report a still-running owner's attempt as crashed. A busy lease
   means that another process owns this work; it must not trigger recovery.
3. Call `Begin`. Only `admitted=true` permits a bounded OS attempt. That return
   requires exclusive intent creation and a successful reload of matching durable
   evidence while the task is still live. A lost commit response, expired task,
   conflicting context, changed ciphertext or different nonce never admits work.
4. An existing intent never permits another mutation. `Lookup` returns the exact
   cached receipt if present. After excluding a live owner, an intent without a
   receipt requires an uncertainty report and independent native escrow recovery.
5. Create a signed encrypted result and call `RecordResult` before transmitting
   it. Retain the exact encrypted result in memory for persistence retries. A lost
   storage confirmation can be retried without regenerating ciphertext. Only an
   identical saved receipt is accepted; a conflicting result cannot replace it.

`Lookup` and `RecordResult` allow receipts after the execution deadline, while
still requiring the active signing certificate and exact scope, context and nonce.
`Begin` rejects expired execution. An orphan result, malformed framed record,
noncanonical JSON, changed signature or foreign installation binding fails closed.

The eventual driver must validate the old PRK before mutation, pass keys only via
owned standard-input buffers, preserve any returned candidate even if validation
cannot complete, and persist its encrypted result before network delivery. Native
MDM escrow must already be active: a process can die after the OS changes a key
and before local receipt persistence. The journal cannot make those two systems
one atomic transaction and does not claim to recover an unpersisted plaintext key.

## Process lease

The root Mac implementation opens a fixed empty `.filevault-rotation.lock` file
relative to the already provisioned private enrollment directory. It pins the
directory descriptor, rejects final symlinks, nonregular files, extra hard links,
wrong owners, group/other access and unexpected contents, and verifies the named
objects still match their opened descriptors. The installer must keep ancestor
directories protected from untrusted renames. It does not create directories or
repair existing access controls.

A nonblocking exclusive `flock` excludes independent processes. Keep the lease
until the journal operation, OS mutation and encrypted receipt persistence finish.
Closing it or terminating its process releases the kernel lock. The empty file
is deliberately never unlinked, so another owner cannot lock a replacement inode
while an existing descriptor remains locked. The lease contains no secret or
execution evidence; the protected journal retains that evidence after a crash.

## Tests

Common tests cover concurrent admission, restart, lost intent and receipt commit
responses, immutable result retries, ciphertext and nonce conflicts, corrupt and
orphan records, bounded names/ordinals, expired execution, late encrypted receipts
and closed-store rejection. A tagged macOS test runs the same durable lifecycle
against a disposable noninteractive keychain; native Windows CI checks the same
record lifecycle through its DPAPI backend. All test keys are synthetic. No test
executes `fdesetup`, reads workstation encryption state or changes a real key.
Mac lease tests use private temporary directories, concurrent handles and a
separate helper process that is killed to verify automatic kernel release. They
also reject unsafe path/file types without altering existing state.
