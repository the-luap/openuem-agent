# Activate a completed macOS enrollment

The installed macOS agent handles `activate` before opening its logger or starting
inventory. It validates the completed native identity and its executable binding,
prepares protected operational configuration, registers the bundled LaunchDaemon
through `SMAppService`, and waits for an authenticated local readiness proof.

Use the final root-owned, Developer ID signed and notarized app installed at the
fixed location. Enrollment must already have been completed by this same signed
executable, with the previously authorized organization/site and management
consent. The identity directory is fixed by the sealed daemon property list:

```sh
sudo '/Applications/OpenUEM Agent.app/Contents/MacOS/openuem-agent' activate \
  -identity-directory /Library/OpenUEMAgent/identity
```

This is an administrator deployment interface. App assembly, installation, release
signing/notarization and an end-user consent interface remain separate release
work. It does not register a new device, consume an invitation, change identity
keys or accept a server, bundle location or service-name override.

## Installed app admission

The completed System-keychain identity must match macOS, the native architecture,
an unexpired device certificate and the stored nonzero release checkpoint. Its
admitted executable size and SHA-256 must match the retained running image before
configuration, registration, readiness waiting and successful return. The daemon
independently verifies that binding during individual-agent initialization.

The app must be `/Applications/OpenUEM Agent.app`. Foundation must identify this
same app and executable as the current process's main bundle. Its app identifier
is `org.openuem.agent`; the daemon label is `org.openuem.agent.daemon`. Both property
lists must exactly match the supported [bundle builder](macos-app-bundle.md)
layout, apart from its allowed release version/build values. Duplicate/extra keys,
different accounts, arguments, identity locations and environment overrides fail.

The verifier retains code-directory and file descriptors, rejects final symlinks
and unsafe ownership/permissions, and rechecks file identity and immutable metadata
including `CodeResources`. Bundle contents must be root-owned without group/other
write access. Root and `/Applications` are retained too; standard root:admin 0775
access on `/Applications` is supported. System administrators remain trusted
installation actors. The installer must establish trusted ancestor ACLs: these
POSIX checks are not a complete ACL or hostile-administrator audit.

`codesign --verify --strict --all-architectures --deep` checks the sealed app with
an explicit requirement for Apple's certificate chain, the Developer ID Application
leaf extension, the OpenUEM app identifier and notarization. A development,
installer or ad-hoc signature is insufficient. The independent release manifest's
agent hash remains the release authorization; an arbitrary Developer ID cannot
authorize different agent bytes. Native assessment never signs the candidate,
changes Gatekeeper rules, removes quarantine or adds trusted certificates.

Apple describes [code requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
and [notarization requirement verification](https://developer.apple.com/videos/play/wwdc2019/703/).

## Configuration and authorization states

Configuration is published at
`/Library/OpenUEMAgent/etc/openuem-agent/openuem.ini`, with private root-owned
configuration directories and a complete, exclusively published mode-0600 INI.
The file carries the individual-enrollment marker and assigned device ID. File
transfer and remote assistance start disabled. Valid operational changes remain
intact on retry; foreign, unmarked, linked or unsafe configuration is preserved
and rejected. Log storage is prepared at `/private/var/log/openuem-agent`; the
logger's standard `/var` alias is checked. A preexisting log without a matching
marked configuration is rejected instead of being adopted.

Registration uses the current app's bundled daemon definition. Existing eligible
or approval-pending registration is reused. The flow never unregisters, stops or
replaces a legacy job. An app or identity update needs a separately authorized
migration; replacing executable bytes invalidates the existing enrollment binding.

Apple distinguishes a registered service that is eligible to run from one that
still needs administrator approval. Eligibility alone is not proof that the agent
initialized. [Native registration behavior](https://developer.apple.com/documentation/servicemanagement/smappservice/register())

Pending or revoked approval returns exit status **3**, a public result such as:

```json
{"registered":true,"running":false,"approval_required":true,"device_id":"6f73f916-8aaf-4cd1-92e9-c8cbb11028ba","tenant_id":3,"site_id":4}
```

An administrator must allow OpenUEM Agent in System Settings > General > Login
Items, then retry the same activation command. The command does not open Settings
or change that consent itself. Cancellation after native registration retains the
registration and reports its observed public state when available.

Once eligible, the command verifies the daemon's
[local readiness proof](macos-local-readiness.md), then rechecks authorization and
configuration. Wrong identity/key, scope, image, native PID or endpoint ownership
fails. An absent or initializing endpoint is retried within the command deadline.
`running: true` means an authenticated local agent initialized; an offline reconnect
schedule may satisfy it. Check remote connectivity, inventory delivery and actual
management results in the console.

Success returns exit 0; invalid arguments return 2, pending approval 3,
cooperative cancellation 130 and other failures 1. Completed identity and
configuration remain on failure. Waiting and signature subprocesses use a
two-minute context deadline, and canceled subprocesses are joined. Apple's
registration/status methods are synchronous and cannot be interrupted during a
native call; this is not a hard wall-clock bound on those framework methods.
The macOS command handles both interrupt and termination signals through that
context; an abrupt process kill or operating-system shutdown can still bypass
local cleanup.

## Verification and remaining acceptance

Portable tests exercise registration state transitions, concurrent attempts,
signature-admission failure, cancellation before/after registration, preserved
pending approval and resource ownership. Native macOS tests use generated private
fixtures to check protected INI publication, competing publishers, unsafe/linked
files, foreign logs, approval/retry behavior and refusal of missing or mismatched
readiness. A separate subprocess runs an actual copied, ad-hoc-signed test
executable inside the generated app: Foundation resolves its current bundle and
performs a read-only `SMAppService` status query. Native code-signature and
requirement-compiler tests establish a resource seal, reject changed resources and
reject ad-hoc signing as Developer ID/notarization evidence.

CI repeats the filesystem and read-only framework fixtures under root through
`scripts/check-macos-activation.sh`. These tests use fake registration controllers
for state transitions; they never register/unregister a native daemon, start
inventory, access production identities or change System/login keychains. The
existing root Unix-socket suite separately verifies actual peer credentials and
authenticated readiness. Full agent builds and app assembly include the real
activation entry point and linked ServiceManagement framework.

A positive installation/registration/approval/reboot test with the final Developer
ID signed and notarized release is still required, along with supported-version
and physical Mac acceptance. The available ad-hoc fixtures cannot prove that
external release gate. Signed installer distribution, guided end-user consent,
authorized binding migration and secure updates also remain open.
