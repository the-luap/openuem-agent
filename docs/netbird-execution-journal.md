# NetBird execution journal

The agent contains an expiring-command executor, private local journal and joined
broker service adapter for NetBird `up`, `down`, `switchprofile`, and version-two
`register` operations.
The journal also recognizes exact version-three Unix installation attempts and
their recovery evidence. The production installation runner is not connected;
new installation commands are explicitly rejected before an attempt is written.
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

Registration exclusively uses version two and requires a bounded `setup_key`.
Version-one connection encoding and hashes remain unchanged. Before creating a
provider key, a console must receive a correlated `registration-state` response;
an ordinary `state` response does not establish registration support. The agent
executes the retained fixed-binary sequence with the key only in the `up` child
environment. The command hash covers that key; journal and control receipts
retain only the hash. Replay after close/reopen does not repeat registration.
Registration receipt queries and explicit releases preserve the same original
uncertainty rules, without claiming provider cleanup or peer ownership.

Installation exclusively uses version three, an individual device/certificate
identity and the complete approved Unix package descriptor. It has no management
URL, profile or setup key, and its organization must match the recipient. Its
ten-minute deadline bounds native execution after separate package preparation.
The journal persists only the complete command digest and ordinary attempt/result
metadata; private sources are never written to it. Retained installation records
cannot appear under a legacy shared-identity journal anchor.

The executor uses a separate installation runner within the same serialization,
permanent UUID namespace and uncertainty barrier as connection and registration.
There is no fallback to the connection CLI runner. An absent installation runner
rejects new work, while an exact existing result remains readable after restart,
expiry or runner removal. Ordinary/registration state does not advertise an
installer capability. [Authenticated private preparation](netbird-package-preparation.md#authenticated-service-ownership)
now shares the service lifetime and executor exclusion. Current console
approval/revocation checks, atomic consumption of the exact prepared package and
native resulting-state verification remain required before supplying the
production installation runner.

Owned tests supply inert installation callbacks to verify admission before any
execution, longer-deadline persistence, package-digest conflicts, concurrent
connection/registration exclusion, lost replies, explicit withdrawal, restart,
later-boot recovery and retained source privacy. They do not install NetBird.
The installation-command checkpoint used shared revision
`d0a53880dcbf2ceae01c4484bf9b7f4429ff0281`; the later authenticated preparation
contract is pinned at `fbef45520563fa80ee2809ca815cd2e8a1c549bd`.
macOS and Linux journal/command/preparation race suites, native service/broker
regressions and all three complete agent platform builds pass. The final
installation-specific suite also tests exclusion in both directions: an uncertain
connection or registration cannot be bypassed by a new installation command.

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
history. The journal has a hard limit of 4,096 attempts/withdrawals and does not prune
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
expiring resolution request and presents uncertainty for operator review before
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
Original unconfirmed outcomes remain unchanged. Managed registration and
combined provider/agent resolution are implemented in the console. Unknown
provider key identity, undelivered control requests and uncertain execution after
a withdrawal conflict still need explicit recovery. Installation/uninstallation,
authoritative peer deletion and physical device acceptance remain open.


## Permanent withdrawal before execution

Control version two requires the original UUID, complete command digest,
revision and operation under current identity. A correlated version-two receipt
query proves support and can report missing evidence; it does not itself authorize
new work. An explicitly reviewed `withdraw` control atomically refuses every
existing execution attempt and stores a permanent `withdrawn` record before
returning its resolution UUID. The original command can no longer be admitted,
including when its broker delivery arrives later or after service restart.

Withdrawal records contain only bounded receipt metadata, resolution identity,
recorded time, native boot evidence and sequence index. They use the same private
atomic publication path and contiguous sequence as execution attempts. Capacity,
clock rollback, ownership, duplicate/corrupt records and publication failures
remain enforced. A missing earlier withdrawal cannot become an empty slot before
a later execution. Old agents reject the unfamiliar record rather than opening
an empty history. Coherent rollback of the entire protected journal remains
outside local storage guarantees; do not restore old history to repeat work.

A same-identity withdrawal is idempotent; another resolution UUID or different
reference metadata conflicts. Version-two receipt queries recover retained
proof without repeating the mutation, using a renewed current certificate while
preserving the original digest. Version-one control queries cannot establish this
new capability. A retained completed or unconfirmed execution cannot be rewritten
as withdrawn. Journal admission and withdrawal share one mutex, so a simultaneous
command either starts with permanent attempt evidence or is permanently denied.

Owned race, filesystem and broker tests cover both orderings, response loss,
late registration delivery, restart, certificate renewal, corrupt and missing
records, capacity, cancellation, expiry and publication failure. The broker tests
replace the command runner and verify zero CLI calls for withdrawn registrations.
Console resolution requires provider key absence before requesting withdrawal
and matching permanent proof before opening its own admission barrier.

## Prepared native installation admission

`BeginPrepared` adds an atomic ready-revision check for new version-three
installation attempts. The service acquires the exact private preparation and
performs native preflight before calling it, while retaining the common executor
and preparation ownership. A withdrawal between inspection and journal admission
invalidates the preparation revision before any installer can run. Exact retained
receipts still replay without another native invocation. The
[native installation contract](netbird-native-installation.md) describes receipt,
payload and CLI-path verification, joined cleanup and remaining console delivery.
