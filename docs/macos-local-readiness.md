# Authenticated local macOS agent readiness

The macOS individual-agent runtime exposes a local readiness endpoint after
successful initialization when its protected enrollment contains the admitted
executable's size and SHA-256. The listener is created after initial configuration
and job registration succeed. It becomes ready after the scheduler starts. An
initialized reconnect schedule can be ready while the broker is offline: this
proof does not report remote connectivity, inventory receipt or compliance.

Legacy mode and earlier identities without executable bindings do not publish
this endpoint. macOS service activation will use it after native registration and
administrator approval; that activation integration is still pending. The agent
continues to use its explicit `serve -identity-directory` interface. No new public
command installs, registers or changes an OS service in this change.

## Authentication and admission

`internal/localready` accepts only root for its public `Listen` and `Probe`
functions. The directory must be an existing, root-owned private identity
directory. The final directory, address and lock entries reject symlinks and
unsafe POSIX ownership/permissions. Trusted installation ancestors and ACLs remain
the caller's responsibility; these checks do not attest a hostile root account or
audit every filesystem ACL.

The directory holds an immutable random address file, an advisory singleton lock
and a mode-0600 Unix socket. The daemon retains the directory and lock descriptors.
A second daemon cannot replace an active endpoint. Restart retains the address;
after an actual process crash it can reclaim an inactive socket at that protected
address while holding the singleton lock. Foreign files and active sockets are
preserved. Close removes only its own socket inode through the retained directory
descriptor. Address and lock metadata remain for the next start.

Both peers inspect native Unix peer credentials. A probe verifies root ownership
and the kernel-reported server process ID, sends 32 cryptographically random
bytes, then verifies a domain-separated Ed25519 proof using the stored broker
public key. The canonical, bounded response binds that nonce and process ID to
the device ID, tenant, site, release digest, admitted executable size/hash,
certificate expiry and readiness state. It contains no private key, enrollment
invitation, broker token, command or mutable client-supplied identity. Different
keys, scope, image, PID, signature domain, replayed responses and noncanonical
messages fail. Socket aliases and replacement during a successful proof fail.

The protocol performs one exchange per connection, limits responses to 2 KiB
plus framing/signature and uses a two-second deadline. At most eight requests may
be active; admission additionally allows eight requests per second with a burst
of eight. Client cancellation closes the connection. Daemon cancellation stops
admission and closes accepted connections, including clients that sent an
incomplete request. The listener borrows the existing signing key, and joined
shutdown waits for every admitted handler before the agent releases that key.
It does not claim a deadline for an uncooperative signing implementation or for
all other agent OS work.

## Verification

Portable protocol tests cover successful readiness, incomplete initialization,
replay and identity/signature mismatch, malformed or oversized responses, expired
identity and cancellation. Agent lifecycle tests verify initialization order,
partial listener failure, canceled startup and key ownership during shutdown.

Native macOS race tests use isolated short `/tmp` directories and actual Unix
peer credentials. They exercise singleton admission, restart, a subprocess that
exits without cleanup, foreign file/socket preservation, socket alias rejection,
idle/stalled clients, cancellation and a deliberately held signing operation.
The ordinary suite verifies non-root rejection. CI additionally compiles this
package's test executable and runs it as root using
`scripts/check-macos-readiness.sh`, exercising the public root-only entry points.
These root fixtures contain no inventory runtime, native keychain backend,
installer or service registration. They do not access production identities or
change System/login keychains, launchd or installed apps.

The existing service lifecycle tests remain separate: a valid local proof is
neither an `SMAppService` registration test nor end-to-end acceptance of a signed,
notarized installation on supported physical Macs.
