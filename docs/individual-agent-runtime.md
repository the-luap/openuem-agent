# Individual agent runtime integration

The Windows/macOS service can now select the protected individual identity before
reading any legacy certificate files. This is an opt-in integration path. Signed
bootstrap authorization, the native enrollment command, installer distribution,
renewal and production console/deployment wiring are not complete yet.

## Selection and configuration

An installer-controlled service environment selects the mode:

```text
OPENUEM_INDIVIDUAL_AGENT_MODE=true
OPENUEM_AGENT_IDENTITY_DIRECTORY=<absolute protected enrollment directory>
```

The directory must already contain a completed enrollment created by the
[protected enrollment store](individual-identity-storage.md). On Windows it is
accessible only to Local System/Administrators. On macOS the root daemon opens
the System-keychain namespace derived from that directory, using the same signed
agent application that created the records. Pending, missing, corrupt, inaccessible,
expired or platform/architecture-mismatched state fails startup without trying
shared credentials. There is no Linux native storage implementation.

An empty/`false` mode with no identity directory retains legacy configuration.
Unknown boolean values, a directory supplied without individual mode, relative
paths and an enabled mode without a directory are rejected. Mode is selected
once at process startup, not by a message from the broker.

The existing installer-owned INI still supplies operational settings. Its minimal
individual-mode content is:

```ini
[Agent]
UUID =
Enabled = true
ExecuteTaskEveryXMinutes = 5
DefaultFrequency = 15
Debug = false
SFTPPort =
VNCProxyPort =
SFTPDisabled = true
RemoteAssistanceDisabled = true
```

`NATS` and `Certificates` sections are unnecessary in this mode. Device ID,
organization and site come from the protected issuance record; INI fields cannot
replace them. SFTP/VNC ports are cleared and remote-assistance flags are forced
off after config reads and before writes. The service does not subscribe to the
legacy VNC/RustDesk controls or the global `agent.newconfig` subject. It obtains
remote operational settings through the device-scoped request instead.

## Transport and commands

The service connects only to the stored, certificate-validated
`wss://<authorized-origin>/agent-channel` endpoint. It proves possession of the
individual NKey and can present its individual client certificate without writing
the private key to a PEM file. Gateway server trust comes from the operating
system's TLS roots; the returned device issuer is never used as a gateway root.
Broker discovery and TCP/shared-certificate fallback remain disabled.

Report, remote config, deployment-result and Windows/macOS profile requests use
`uem.v1.agent.<issued-id>.request.<operation>` and the library's private reply
inbox. All existing request call sites go through that selector. Individual
requests reject unknown operations, bodies larger than 8 MiB and timeouts outside
the positive ten-minute bound. Service cancellation interrupts pending requests.
The worker independently checks body/device/organization/site bindings.

The endpoint opens only its pre-provisioned command consumer using shared-library
`OpenAgentCommandConsumer`. It verifies the fixed configuration and does not send
stream or consumer creation/update requests. Provisioning delays retry the read
every five seconds. Pulls request one message at a time with a 25-second expiry.
The runtime joins consumer shutdown before releasing its key owner and waits for
the broker's close event. Duplicate connection calls reuse the active connection;
concurrent stop calls run cleanup once.

Enable, disable and report commands use the existing agent handlers. Legacy
certificate/private-key delivery is excluded. Durable updater/rollback/uninstall
commands are not implemented in this runtime yet; unsupported commands receive a
delayed negative acknowledgment and stay subject to the server's five-delivery
limit for operator investigation. They are not silently reported as successful.
Existing software/profile handlers still need complete execution time bounds,
service-start/stop acceptance, signed updater integration and physical device
validation. Cancellation of a broker request does not cancel every inherited
inventory or operating-system subprocess.

## Automated evidence

All three CI platforms build the entire agent and run:

```sh
go test -count=1 ./internal/enrollmentstore ./internal/agent
```

macOS enables CGO and the explicit isolated-keychain test tag; Linux/macOS also
run the race detector. Agent tests parse an isolated INI without any shared
certificate files, preserve issued scope against conflicting INI values, and use
the actual `SendReport` function against a real TLS WebSocket NATS broker with
individual subject permissions. They verify private replies, server-trust
separation, prepared-consumer use and shutdown cancellation. Test reports contain
synthetic data; tests do not run host inventory, install software, enroll the
workstation or execute power/update commands. Related console tests separately
exercise the real TLS gateway and PostgreSQL issuer.
