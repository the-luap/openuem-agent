# Protected individual identity renewal

The agent pins shared library
[`06ec5c5`](https://github.com/the-luap/openuem-nats/commit/06ec5c578a4f8682a223fb42bbea10b4febe0a94)
and implements a persistent candidate/activation journal in `enrollmentstore`.
The [shared-library CI](https://github.com/the-luap/openuem-nats/actions/runs/34471335722)
passes Linux/PostgreSQL/race/fuzz and native Windows checks. Console
[`3a49b79`](https://github.com/the-luap/openuem-console/commit/3a49b79fc9a2e8ed331da3cd2b0bc8ffd322941b)
provides the exact HTTPS/gateway routes; its
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34472855743) and
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34472852010) pass.
See the [server lifecycle](https://github.com/the-luap/openuem-console/blob/3a49b79fc9a2e8ed331da3cd2b0bc8ffd322941b/docs/desktop-identity-renewal.md)
for registry authorization, permanent key ownership and FileVault reconciliation.

This is an implemented storage and transport component. The installed service
does not schedule or invoke automatic renewal yet. Runtime quiescence, startup
recovery, broker/recipient reconnect, an authoritative server cancellation path
for unresolved expired confirmations and release integration remain necessary.

## State transitions and ownership

`Store.PrepareRenewal(ctx, roots)` generates a fresh RSA certificate key, NKey
broker key and request UUID. It publishes the complete candidate exclusively,
then reloads the durable winner before sending either public-key proof. Competing
processes retain one candidate. Preparation is initially attempted only within
30 days of current certificate expiry, with more than five minutes remaining;
the server independently enforces its authorization and issuance window.

The method uses the shared verified HTTPS client and the original protected
origin. `roots` supplies independently authorized HTTPS roots; nil uses system
roots. Response certificates cannot establish transport trust. A lost response
keeps the candidate and UUID. A retry creates fresh proofs for that same intent,
recovers exact server issuance and retains the verified response before returning
it. Preparation preserves current credentials and the original installation.

`Store.ConfirmRenewal(ctx, requestID, roots)` requires callers to stop old
credential users and security-task execution first. It records one exclusive
`confirm` decision bound to exact retained issuance before any confirmation I/O.
Another process may observe and use that decision. Consequently, even cancellation
before this caller transmits cannot authorize discarding it. Candidate proofs are
created from the protected keys; the verified acknowledgement is persisted before
the new identity is returned. Both keys and the complete candidate certificate
must match, including device/scope/origin and bounded response times.

The store cannot revoke key objects already returned to another caller. The
runtime must coordinate credential ownership, stop and join existing users, and
only then perform the handoff. A successful return owns independent decoded keys;
close that identity only after its users stop. Reconstruct the broker TLS/NKey
connection and register the recovery recipient under its new server epoch.

| Local state | `Load` behavior | Recovery |
| --- | --- | --- |
| Candidate or prepared issuance | Returns the current identity only while it remains valid | Retry preparation with the stored candidate |
| Confirm decision without local activation | Returns `ErrRenewalHandoff`, including after source/preparation expiry | Retry confirmation for the exact retained request ID |
| Persisted verified activation | Returns the current replacement identity after validating it at the current time | Exact confirmation retries return that same current generation |
| Explicitly abandoned candidate | Preserves the preceding current identity and all records | A later candidate still obeys the server's pending-preparation guard |
| Corrupt, inconsistent or missing dependent records | Fails without replacing evidence or returning older keys | Investigate and recover the complete protected installation |
| Exhausted attempt capacity | Still returns a valid current identity; preparation rejects another attempt | Preserve the complete history for an explicit future migration |

`Store.RenewalStatus()` returns only the pending request ID, `candidate`, `prepared`
or `confirming` stage, and preparation expiry when known. It holds no private key.
A nil status means there is no unresolved local attempt; use `Load` to check that
the selected identity is currently usable.

`Store.AbandonRenewal(requestID)` is a separate explicit local decision. It can
win only before any `confirm` decision. Confirmation and abandonment contend for
the same immutable record, so both cannot be authorized. Abandonment never deletes
keys or cancels a server reservation. A subsequent candidate may receive the
server's `pending` conflict until the earlier preparation expires. No method
automatically abandons a candidate or retries network requests.

An error or cancellation after confirmation may follow a committed server handoff.
The journal never falls back to old credentials or permits abandonment based on
that error, preparation expiry, a process restart or an expired original leaf.
Fresh candidate proof can recover a committed result after source expiry while
the candidate remains valid. A denied, uncommitted confirmation that has passed
server expiry still needs a separately authenticated server-side cancellation or
recovery contract; the current journal deliberately retains that unresolved state.
An earlier confirmation cannot roll back a later generation.

## Immutable native records

The original `pending` and `identity` records remain untouched. Their protected
bootstrap, request keys, assigned device/scope, release checkpoint and installed
executable binding anchor all generations. Only the selected current certificate
is required to remain unexpired. The original response is verified during the
signed issuer/leaf validity overlap; every later proof and response is verified
at its retained authenticated transition time before traversing the chain.

For each ordinal from 1 through 128, the native backend accepts exactly:

```text
renewal-candidate-v1-NNN
renewal-issued-v1-NNN
renewal-decision-v1-NNN
renewal-activated-v1-NNN
```

The bounded binary framing uses separate versioned purposes for each stage:

- Candidate: original pending digest, exact ordinal, source certificate digest,
  initial signed request, and candidate private keys bound to the same bootstrap.
- Issued: candidate record digest, fresh preparation proof, exact public issuance
  and receipt time.
- Decision: candidate record digest, `confirm` or `abandon`, decision time and,
  for confirmation only, the exact issuance record digest.
- Activated: decision record digest, fresh candidate confirmation proof, exact
  public acknowledgement and receipt time.

Existing DPAPI/System-Keychain protection, record-name binding, exclusive durable
publication, application/owner access restrictions and 128 KiB plaintext record
bounds apply. Private material is never serialized to HTTP, configuration or logs.
Owned temporary private buffers are cleared; Go can retain internal RSA/runtime
copies, so this does not promise complete in-memory erasure. Record slots and old
protected keys are permanent and count toward the 128-attempt cap, including
abandoned attempts. There is no implicit garbage collection or slot reuse.

Loads inspect all bounded slots, including later fragments after missing records.
Stage digests, ordinals, proof signatures, candidate private/public keys, scope,
time ordering and request uniqueness must agree. Missing original anchors with
surviving renewal records cannot create a fresh enrollment or zero checkpoint.
Missing final activation preserves confirmation uncertainty; missing earlier
stages or a gap before a later generation fails closed. Native read failures are
not treated as absent history. A concurrent publication can require a retry;
an inconsistent read cannot supply older credentials after observing handoff.
Complete rollback or loss of all protected evidence still needs an independent
recovery policy.

## FileVault continuity

Recipient and rotation anchors retain their original pending-record digest,
device, scope and origin. Renewal does not change the local X25519 recipient key,
old encrypted receipts, nonces, boot evidence or permanent rotation ordinals.
The server requires a fresh recipient registration epoch for the new certificate.

The selected identity carries authenticated public certificate history. A new
rotation journal can read a retired generation's exact receipt using its original
certificate and the HTTPS-authenticated retirement time, even after that leaf
expires. Such a read cannot admit another mutation or produce a new signed result
under the retired generation. New intent/result publication checks the currently
selected protected identity again; confirmation uncertainty and stale journal
handles fail closed. Reusing an earlier ordinal with another context is rejected.
The runtime must still hold the established process lease throughout OS execution
and stop all such work before invoking confirmation.

The registry independently requires completion/reconciliation of delivered
security work, including a console acknowledgement after returned FileVault keys
and audit are durably retained. Local receipt preservation does not replace that
server-side key-processing requirement. Historical server rows predating those
acknowledgements need their separate verified reconciliation path.

## Verification

The previous partial-restore hardening at agent
[`39d574a`](https://github.com/the-luap/openuem-agent/commit/39d574ad4f18242cf9a5b6ddb0342e828fb8992e)
passes [Linux, native macOS and native Windows CI](https://github.com/the-luap/openuem-agent/actions/runs/34473460694).
The renewal suite additionally covers:

- Real SDK HTTPS/HTTP2 with native candidate/decision checks at the first network
  boundary, lost preparation/activation replies and reconstructed stores.
- Failures before and after each of the four native publications; no premature
  issuance, old-key fallback, duplicate activation or altered installation anchor.
- Concurrent preparation/confirmation, exclusive confirm-versus-abandon decisions,
  server-pending reservations after local abandonment and cancelled committed replies.
- Invalid issuance/confirmation responses, missing/corrupt records, later orphan
  fragments, fixed record names and a complete exhausted 128-attempt history.
- Recovery after original certificate/preparation expiry, multiple generations,
  unchanged release checkpoint and rejection of earlier confirmation rollback.
- Stable FileVault recipient key, original receipt verification after source
  expiry, stale journal rejection and permanent ordinal continuity.

The final local native macOS race suites pass: protected enrollment store in
**30.632 seconds**, agent runtime in **9.053 seconds**, bootstrap installation in
**1.555 seconds**, enrollment command in **1.826 seconds**, activation in
**4.516 seconds**, service lifecycle in **1.292 seconds** and Mac service in
**3.456 seconds**. The native fixture uses a disposable noninteractive keychain;
the equivalent DPAPI fixture is compiled locally and executed by Windows CI.
Affected-package Vet, module consistency and complete Linux/Windows/native-macOS
builds pass. The CI run for this new journal must be checked independently of
the earlier partial-restore run above.

These checks use synthetic keys, a local HTTPS issuer and owned native stores.
They neither install an agent nor run FileVault on a real volume. Automatic
service scheduling/reconnect, authoritative cancellation, historical server
reconciliation, production signing/releases, CA/master-key rotation and physical
Windows/macOS acceptance remain open parts of the full roadmap.
