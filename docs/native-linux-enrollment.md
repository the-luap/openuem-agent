# Native Linux enrollment

The installed Linux agent accepts `enroll` before opening its logger or starting
service work. The command uses the same explicit consent, independent HTTPS
origin, organization/site authorization and public JSON result as the
[native enrollment interface](native-enrollment-command.md). AMD64 and ARM64
targets use the actual running architecture. It does not install the downloaded
package or register/start a service.

## Required installation inputs

Run the installed executable as root. Provision these prerequisites independently
of the downloaded enrollment configuration:

- A canonical HTTPS origin, positive organization/site IDs and explicit
  `-accept-management` consent.
- A private invitation file and independent release-signing public keys, using
  the documented bounded token/PEM formats. Linux requires root-owned regular
  files with mode `0600`, one hard link and canonical absolute paths. Every
  ancestor must be root-owned, without group/other writes, symlinks or special
  permission bits. Descriptor-relative opens and post-read identity/metadata
  rechecks bind each copied input to its protected namespace.
- Distinct native identity and staging directories below existing protected
  root-owned parents. Only final private directories can be created; unsafe
  existing trees are rejected without permission changes. Staging preflight
  rejects unsafe parents before directory creation or network access.
- The existing [systemd host credential key](linux-credential-encryption.md),
  native `systemd-creds` and [encrypted identity backend](linux-identity-storage.md).
  Enrollment never generates or replaces the operating system's host key.
- Independently provisioned [DEB/RPM publisher trust](linux-package-signatures.md)
  and native verification tools. An authentic release manifest cannot authorize
  a foreign or unsigned package publisher by itself.

The Linux [running-image provider](linux-running-executable.md) retains both the
kernel-selected executable and its protected canonical path. The signed
`agent_size`/`agent_sha256` must match that exact running ELF image. This binding
is independent of the package's signed size/hash. A copied identical file at a
different inode cannot substitute for the running executable.

## Enrollment and recovery

After authenticating the exact invitation/scope and signed bootstrap/release
data, the command downloads the approved package through exact-origin HTTPS and
uses [protected native staging](linux-package-staging.md) to verify its publisher.
The executable and staged file remain retained throughout the store's admission
checks before pending-key creation, before the claim and before publication.

Completed identity state records the Linux platform, architecture, signed release
checkpoint and separate agent byte binding. Repeating the same valid command
returns the protected identity without making a second claim. Cancellation after
server issuance retains pending keys; a subsequent valid retry proves ownership
of those same keys and recovers the issued identity. Failed native trust, scope or
executable checks prevent the claim and pending-key publication.

Only the current operation's owned staging files are cleaned up. Input files and
durable identity state remain available for recovery. `identity_ready` reports
credential persistence. Service registration, local readiness and console
connectivity need their own evidence.

## Verification

`scripts/check-linux-enrollment.sh` runs in a disposable, network-isolated Linux
container with a read-only filesystem and private tmpfs mounts. A synthetic
machine ID and generated systemd host key isolate encrypted state from the host.
Two generated package publishers produce inert DEB/RPM fixtures; only one is
trusted. Signing private keys are removed before Go tests begin. Packages are
verified but never installed or executed. The HTTPS fixture uses loopback and
adds only its owned test issuer through a private test dependency; production
exposes no alternate-root or native-verification bypass option.

The full command race suite passes in 5.554 seconds. Five native test families
must explicitly pass: complete DEB/RPM enrollment and retry, publisher/agent/scope
rejection before claims, interrupted issuance with original pending keys, unsafe
input/staging rejection before HTTPS, and retained-ancestry/byte-limit checks.
macOS enrollment/bootstrap/activation regressions pass in 1.871/2.048/4.780 seconds;
complete Linux and Windows builds and Linux enrollment Vet checks also pass.
CI adds a dedicated native enrollment job and invokes help through the actual
Linux service entry point.

The later [native Linux readiness integration](native-linux-readiness.md) also
verifies the completed encrypted identity can authenticate the local endpoint,
including long canonical identity paths. With this sixth required family, the
full enrollment race suite passes in 6.464 seconds. Enrollment commit `04fb25c`
passes all twelve [CI jobs](https://github.com/the-luap/openuem-agent/actions/runs/34889458491).
Linux service activation, final installers, publisher/release provisioning and
physical installation/removal acceptance remain separate integration work.
