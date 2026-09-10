# Private FileVault rotation

The individual Mac agent implements encrypted rotation protocol v2, a protected
attempt journal, a private process lease and a bounded local OS driver. Execution
requires both `recovery_task_version: 1` and `rotation_task_version: 2` from a
compatible worker, an accessible journal and an encrypted authorized task.
Absent, unsupported or legacy capabilities never enable rotation. Worker routing,
console escrow authorization and physical Mac acceptance are separate integration
requirements. Existing read-only validation retains its own protocol.

## Durable records

`Store.OpenRotationJournal` verifies the already committed Mac identity and binds
`rotation-anchor-v1` to its exact pending-record digest, origin, device ID and
organization/site. It preserves existing pending, identity and recipient records.
A missing anchor with surviving attempts fails closed. An orphan anchor prevents
the installation from being mistaken for an empty enrollment store.

When pending enrollment keys or the committed identity are missing, the store also
checks every start/result slot, including later ordinals with gaps and no journal
anchor. Any surviving recipient, anchor, attempt or result, or a failed native
read, returns an unavailable-state error before generating keys or transmitting a
claim. A partial restore cannot recreate enrollment around retained irreversible
work. Existing records remain untouched, and lost pending keys cannot reset the
release checkpoint to zero. Ordinary pending-claim recovery remains available
when no dependent security records exist. Complete loss or rollback of all local
evidence still requires an independent recovery policy.

For each ordinal from 1 through 128, only these record names are accepted:

```text
rotation-start-v1-NNN
rotation-result-v1-NNN
```

The start record contains the installation binding, complete rotation context,
32-byte nonce, SHA-256 digest of the exact encrypted task and kernel boot-session
UUID read from `kern.bootsessionuuid`. New records use the v2 start-record framing
inside the same fixed slot names. Legacy v1 records remain readable, without
inventing boot evidence or rewriting their original contents. Neither format
contains a PRK.
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
3. Read `macsecurity.BootSessionID` and call `BeginWithBootSession`. Only
   `admitted=true` permits a bounded OS attempt. That return
   requires exclusive intent creation and a successful reload of matching durable
   evidence while the task is still live. A lost commit response, expired task,
   conflicting context, changed ciphertext or different nonce never admits work.
4. An existing intent never permits another mutation. `Lookup` returns the exact
   cached receipt if present. A free parent lease does not exclude an orphaned
   command. An intent without a receipt stays blocked during the same kernel boot.
   A different boot from the recorded admission permits signed stopping evidence.
5. Create a signed encrypted result and call `RecordResult` before transmitting
   it. Retain the exact encrypted result in memory for persistence retries. A lost
   storage confirmation can be retried without regenerating ciphertext. Only an
   identical saved receipt is accepted; a conflicting result cannot replace it.

`Lookup` and `RecordResult` allow receipts after the execution deadline, while
requiring the exact scope, context and nonce. New result publication requires
the currently selected signing certificate. After [identity renewal](individual-identity-renewal.md),
historical reads use the original certificate and its authenticated retirement
time. They preserve old receipts without authorizing new work under retired keys.
`BeginWithBootSession` rejects missing boot identity and expired execution. An orphan result, malformed framed record,
noncanonical JSON, changed signature or foreign installation binding fails closed.

The runtime validates the old PRK before mutation, passes keys only via owned
standard-input buffers, preserves returned candidates when validation cannot
complete, and persists the encrypted result before network delivery. Native
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
A launched child can survive the parent and continue after this lock becomes
available. Acquiring the lock therefore never proves that the command stopped.

## OS driver and runtime

The driver uses only the root Mac agent and the current process lease. It first
performs the existing bounded read-only validation, then starts this fixed command:

```text
/usr/bin/fdesetup changerecovery -personal -inputplist -outputplist
```

The old PRK is the `Password` value in owned plist bytes on stdin. No shell, secret
arguments, inherited environment, temporary output file or stderr capture is used.
Read-only checks use 15-second contexts, the mutation uses a 30-second context,
and the complete driver uses a one-minute context. All work respects the task
deadline, with a further 500-millisecond pipe-drain bound after cancellation.
The runtime also reserves two minutes before certificate expiry for signing and
durable publication. Lease closure waits for an active driver to finish.

The bounded XML reader selects only the root dictionary's `RecoveryKey`, retains
at most 8 KiB of output, and rejects duplicates, truncation, extra roots, unsupported
types, excessive nesting and oversized dictionaries/arrays. It does not load
external entities or turn the PRK into an immutable Go string. Unexpected output
produces uncertainty. It never infers success merely from a zero process exit.

| Outcome | Meaning |
| --- | --- |
| `rotated` | A different returned PRK passed volume validation. |
| `unverified` | A candidate new PRK is retained, but the process or its subsequent validation did not complete successfully. |
| `uncertain` | The mutation started without a trustworthy new key, or a previous admitted attempt has no persisted result. |
| `invalid` | The old key failed its read-only check before mutation. |
| `unavailable` | Preflight, process start, lease access or certificate reserve prevented mutation. |
| `unsupported` | The OS driver was called outside the root Mac context. |

A returned candidate survives nonzero exit, timeout and shutdown cancellation.
The runtime signs and encrypts it while holding the lease, publishes it to the
journal, releases/clears plaintext and then sends the receipt. Storage retries keep
the exact encrypted bytes; lost network acknowledgements retry the saved receipt.
A restarted runtime reads its journal before decryption or execution. A busy lease
cannot be treated as a crashed owner. An intent-only record during the same kernel
boot waits without reporting or repeating execution. A new kernel boot excludes
the old process and permits an `uncertain` receipt with signed
`execution_stopped: true`. During normal execution, the driver may report this
evidence after `Wait` reaps its exact mutation process. A missing/unknown exit
does not receive this flag. No automatic reboot is performed.

Deadline expiry, reconnecting the agent or changing its PID is insufficient.
Legacy intents without a boot UUID and immutable uncertainty receipts without
the stopping flag cannot authorize automatic old-key resolution. Native escrow
and retained key history remain available for recovery. A receipt request without
local evidence cannot invent an execution nonce or trigger a mutation. Protocol
v2 negotiation prevents an old worker or agent from enabling the new workflow;
validation remains protocol v1 and existing encrypted context bindings are retained.

One owned goroutine serializes registration, read-only validation and rotation,
sharing the protected recipient epoch without races. The enrollment store stays
open through that goroutine's shutdown. Cancellation still permits encrypted
receipt persistence before keys and storage close. Replacing the recipient epoch
stops transmission under the old epoch but preserves its encrypted journal record.

Apple documents the PRK authentication and output-plist options in the installed
`fdesetup(8)` manual; its [FileVault deployment guide](https://support.apple.com/guide/deployment/dep0a2cb7686/web)
also describes the MDM and command-line management boundaries. Actual volume and
native escrow interoperability still require physical-device acceptance.

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
also reject unsafe path/file types without altering existing state. A two-process
fixture proves that the child survives while its crashed parent releases the lease.
A read-only kernel test checks boot UUID availability and stability. Runtime tests
separately verify observed termination, same-boot waiting, simulated subsequent
boots, missing boot evidence and conservative legacy handling.
Driver tests launch only the Go fixture executable and exercise stdin/environment
isolation, all outcomes, timeouts, process-start failure, malformed output,
candidate preservation and secret clearing. Output-parser fuzzing checks bounded
decoding. Runtime tests use a real isolated TLS WebSocket broker, generated HPKE/RSA
keys, an injected journal and driver, and verify durable publication before network
transmission, restart, cancelled shutdown, storage failures, capability gates,
certificate reserve, conflicting scope and recipient replacement.

Partial-restore tests remove enrollment/journal anchors while retaining first,
middle or final attempt/result slots. They verify rejection before any claim or
new key publication, unchanged original fragments, retained pending-key bytes and
no zero-checkpoint fallback. An unreadable final slot also prevents enrollment.
Native fixtures exercise the final result slot through isolated macOS Keychain
and Windows DPAPI storage. The focused local macOS race checks pass in 2.197
seconds; the complete protected-store suite passes in 13.961 seconds and agent
runtime in 11.219 seconds. Bootstrap installation, enrollment/activation commands
and Mac service/lifecycle race tests also pass. Vet, Linux/Windows/native-macOS
builds and Windows test compilation pass; native Windows execution is checked
separately by CI.
