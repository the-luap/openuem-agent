# Mac hardware evidence

The Mac collector runs `/usr/sbin/system_profiler -json SPHardwareDataType` once
per hardware attempt with a 30-second deadline and a 1 MiB output limit. It
preserves the reported hardware model (including `iMacPro1,1`), distinguishes the
hardware platform UUID from provisioning UDID, and accepts numeric or numeric
string core counts. Unrecognized core formats remain unknown (zero); they are
never guessed. Memory retains the existing inventory unit, MB. Hardware without
valid stable identifiers remains ordinary inventory and cannot become association
evidence.

Only an individually enrolled Mac sends version 1 hardware evidence, after an
authenticated worker configuration advertises `hardware_inventory_version: 1`.
The normal desktop report contains no new fields. Legacy runtimes, Windows and
older or unsupported worker capabilities skip the extra request. The configuration
capability is held in memory and renegotiated after restart. Hardware is sent
after the normal report using the device's own NKey-authorized subject and private
reply inbox. A denied or malformed receipt is an error, not a successful report.
The next scheduled report retries the idempotent observation.

At send time, the daemon reads only the system managed-preferences file
`/Library/Managed Preferences/eu.openuem.device-binding.plist`. Missing preferences
mean no proof. A present file must be a bounded regular file owned by root,
without group/world write permission, symlinks or hard links. Parent directories
are opened relative to already-open descriptors with no symlink following and
must also be root-owned and protected. No user preference directory, environment
override or shell command can supply the proof. XML and binary plists must contain
exactly the typed `ChallengeID`, `DeviceID` and canonical 256-bit `Token` values.
Invalid files return a generic error that contains no token or parser input.

The proof travels only in the separate hardware request, never in ordinary
report JSON, inventory output or logs. The worker stores its hash. A serial number
alone does not authorize a link: the console must match the MDM-delivered challenge,
hardware, scope and both current identities. This collector does not itself merge
records or grant access to another management channel.

Deploy the updated registry and broker authorization service first, then the
worker, then agents. Devices must reconnect to obtain updated broker permissions.
The module pins the shared protocol at `4e6e26103fd9`. Fixture tests cover model
preservation, identifiers, absent data, memory/core parsing, both plist formats,
file metadata protections, strict receipts and a real TLS/WSS NATS hardware RPC.
They do not read this workstation's hardware or managed preferences. Physical
MDM profile delivery and system preference materialization remain separate Mac
acceptance requirements.

References: [Apple managed-preferences schema, pinned revision](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/profiles/com.apple.ManagedClient.preferences.yaml),
[Go plist format support](https://github.com/DHowett/go-plist).
