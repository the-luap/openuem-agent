# NetBird execution journal

The agent contains an expiring-command executor, private local journal and joined
broker service adapter for NetBird `up`, `down` and `switchprofile` operations.
Native startup now opens this journal and attaches the production managed
subscriptions. Old mutating NetBird subjects and profile steps are rejected,
including when the managed runtime is unavailable. They cannot bypass a retained
uncertainty barrier or be translated into commands with random new UUIDs.

## Protocol and execution

The shared `netbirdcommand` protocol carries a request UUID, exact device and
organization/site, enrollment mode, certificate hash, source revision, operation,
management URL, profile and an issue/expiry interval of at most two minutes.
Its separate `agent.netbird.command.<device>` subject prevents legacy handlers
from interpreting an envelope as old settings. The strict codec checks required
fields, duplicate/unknown/null fields, types, size and operation inputs.

`DurableExecutor` validates the envelope and reads matching retained evidence
before admitting work. A canonical digest covers all command inputs. It commits
an attempt before calling the existing fixed-binary NetBird action sequence,
applies the command expiry and service context, joins that sequence and commits
its result before returning an execution receipt. A positive result requires the
sequence and bounded observation to succeed before the deadline.

The executor admits one command at a time. Concurrent work receives a correlated
busy receipt. An existing UUID with the same digest returns retained evidence;
different input under the same UUID fails. An expired envelope may retrieve an
existing receipt but cannot create a new attempt. A failed or cancelled command
is unconfirmed. Result persistence failure never returns success and makes the
live journal unavailable. Transport response loss never triggers a repeat CLI
invocation.

## Private storage and identity

`netbirdjournal.Open` requires a trusted installation parent, a stable installation
digest, current device identity and native boot evidence. Its child directory
must be private before any record is written. Existing shared directories fail
without permission repair. Unix uses private service/root-owned files; Windows
uses private service/System/Administrators ACLs. This metadata journal does not
add a plaintext fallback to individual enrollment secret storage.

The immutable anchor binds installation, device, organization/site and enrollment
mode. Renewable certificates are checked against the current caller identity,
while older attempts remain bound to their original command digests. Changing
scope or installation cannot silently create an empty journal at the same path.

Individual startup derives the installation digest from the validated enrollment
origin, exact device/scope, certificate public key and broker public key. It uses
`netbird-journal` under the protected individual identity directory, independent
of versioned executable paths. Renewal changes the current certificate hash and
deadline without changing installation ownership. The prior service must join
before the renewed owner can reopen the same journal.

Legacy startup validates its configured device/scope, client certificate chain,
key pair, expiry and configuration parent ownership. Its installation digest
also binds the configured broker authority. Shared legacy credentials still do
not establish an individual cryptographic device identity. The parent may allow
public reading, but untrusted write access and final symlinks are rejected;
the journal child itself stays private. Runtime configuration scope/mode changes
close the managed service and require a restart with valid retained ownership.

Each attempt has an immutable start record and, when available, an immutable
result and explicit release record. These contain only identifiers, digests,
status, timestamps and native boot evidence. Command URLs, profile names, provider
tokens, setup keys and arbitrary subprocess output are absent.

An OS file lock excludes other journal owners across processes. The owner keeps
the private directory and lock descriptors open and checks their current file
identities. Records must be bounded private regular files with one link.
Symlinks, unexpected names, gaps, orphan result/release records, corrupt or
noncanonical documents and incomplete publication files fail closed. Readers
never turn incomplete data into an empty slot.

Publication writes a private temporary file, syncs and closes it, then publishes
without replacing an existing record. Unix links and removes the temporary name
and syncs the directory; Windows uses a write-through move without replacement.
An interrupted publication may leave an unavailable journal requiring explicit
recovery. Do not delete records or restore a coherent older journal snapshot to
retry a command: local metadata cannot prove what happened outside that retained
history. The journal has a hard limit of 4,096 attempts and does not prune
duplicate-protection records automatically.

## Uncertainty and explicit release

| Retained state | New execution | Explicit release |
| --- | --- | --- |
| Completed result | Allowed | Not applicable |
| Joined, unconfirmed result | Blocked | Allowed after authorized review |
| Attempt without result in the same kernel boot | Blocked | Refused; a CLI process may have survived the agent |
| Attempt without result after a verified later kernel boot | Blocked | Allowed after authorized review |

Restarting the agent alone never establishes that an orphaned CLI stopped. Linux
uses the kernel boot UUID; macOS uses its kernel boot-session UUID. Windows
requires both a later loader sequence and a different original System process
creation time, distinguishing a reboot from process restart, resume and clock
changes. A reboot never automatically releases uncertainty or repeats a command.
Release has its own immutable UUID and preserves the original unconfirmed
outcome. A retained clock watermark also refuses new work after a substantial
clock rollback.

Only a live owner that admitted an attempt may finish it. Recovery can report
that an attempt is unconfirmed; it cannot manufacture a completed result. The
console resolution endpoint authenticates the current target, validates an
expiring resolution request and present uncertainty for operator review before
calling the journal release API.

## Live control and service lifetime

`Journal.Control` validates exact current identity, service cancellation and a
ten-second control expiry after acquiring the journal mutex. State queries are
read-only. Their stable revision binds the installation, identity, boot, attempt
count and last attempt/result/release. Queries report remaining capacity,
pending command identity and whether explicit release is currently possible.
Clock rollback, closed ownership and unavailable storage never report readiness.

Receipt queries use the original command UUID and complete digest under a fresh
current identity. Certificate renewal therefore preserves access to historical
evidence without redelivering the old command. Release and its response are
serialized with journal access. A lost release reply can be recovered by a
read-only receipt query, which returns the immutable resolution UUID. The original
unconfirmed receipt stays unconfirmed.

`DurableService` owns its journal on successful construction. Its caller supplies
a validated identity and certificate expiry and must exclude legacy/profile
mutations before binding subscriptions. The service rejects commands or controls
that outlive that certificate. It creates exact command/control subscriptions,
bounds their pending queues, and preserves the executor/journal when replacing a
connection. A binding token rejects callbacks from superseded subscriptions.
Close atomically stops admission, cancels command contexts and unsubscribes, then
joins admitted handlers before closing the journal and releasing its OS lease.
Callers must retain the native identity until Close returns.

## Validation and remaining integration

Tests use private temporary directories, owned subprocesses and an owned NATS
server. They cover durable replay, response loss, scope/certificate changes,
expiry and cancellation, concurrent execution, cross-process exclusion, corrupt
records and partial restores, permission/link checks, publication failure,
native boot stability and explicit release. Control/service tests additionally
cover certificate changes, lost release replies, live release refusal,
connection replacement and shutdown while a command has not yet joined.
The action runner is replaced with
an owned test callback; these checks never invoke an installed NetBird client or
contact a provider.

Native agent shutdown closes and joins managed execution before releasing the
individual identity or service lease. Native tests cover renewal-stable ownership,
retired-certificate rejection, configuration changes, legacy certificate/parent
validation and old-subject/profile rejection. The Linux agent, journal and command
race suites pass in 28.402, 3.404 and 1.231 seconds.

The console now has review, request, receipt, history and queued cancellation.
Its [reviewed resolution flow](https://github.com/the-luap/openuem-console/blob/7daac02/docs/netbird-resolutions.md)
persists immutable intent before one release control and requires matching
retained evidence before opening console admission. Lost replies use read-only
receipt queries under the current certificate with the same resolution UUID.
Original unconfirmed outcomes remain unchanged. Missing evidence and an
undelivered release stay blocked; no automatic resend or journal reset is used.
Registration,
provider key lifecycle, installation/uninstallation, authoritative peer deletion
and physical device acceptance remain open.
