# Private FileVault recovery validation

The individual Mac runtime supports recovery protocol version 1. After loading
the protected enrollment identity it loads or creates a separate immutable X25519
recipient in the System keychain. It does not reuse the RSA signing certificate
as an encryption key. An unavailable recipient disables this feature and emits
only a generic diagnostic; ordinary authenticated inventory can still run.

The worker must advertise `recovery_task_version: 1` in a successful configuration
response. Older workers, Windows identities and legacy enrollment never start the
poll loop. Update the registry and broker permissions before the worker and agent.
The worker requires an existing inventory record in the correct organization/site.
No durable command subjects or consumer filters change.

A single owned goroutine registers the recipient with a signed server challenge
and polls at most every 30 seconds. Network operations have a five-second timeout.
Every challenge, recipient and HPKE task must match the protected device identity,
organization, site, signing certificate and recipient epoch. Tasks also bind a
native Mac, recovery-key version, task ID and expiry.

Only the root Mac runtime invokes the fixed command:

```text
/usr/bin/fdesetup validaterecovery -inputplist
```

It supplies the strictly validated personal recovery key through owned XML bytes
on standard input. The key never enters arguments, environment variables, a shell,
temporary files, diagnostic messages or ordinary inventory. The check is read-only,
bounded by 15 seconds and the task expiry, drains at most 64 retained output bytes,
and discards stderr. Only a successful process returning `true` reports `valid`;
`false` reports `invalid`. Errors and unsupported execution contexts remain
distinct signed outcomes.

The agent signs the exact outcome, task context and random nonce. It clears the
owned plaintext before sending the result. A lost acknowledgment retains only
the signed receipt in memory; retry does not repeat the local check. Replacing the
recipient epoch or reaching the task expiry discards the old receipt. Process
restart can safely repeat this read-only check if the server still has a pending
task. Shutdown cancels network/process work, joins the goroutine and releases keys.
Go cryptographic internals may retain copies; complete memory erasure is not claimed.

Automated tests use generated keys, a real isolated TLS WebSocket broker, temporary
keychain/DPAPI fixtures, and the Go test executable as the subprocess. They never
execute `fdesetup`, inspect this workstation's encryption, unlock a disk or rotate
a real key. Physical Mac acceptance is still required. The console must separately
authorize and bind a task to the verified native/agent association and verify the
signed result before marking the current recovery key as verified.
