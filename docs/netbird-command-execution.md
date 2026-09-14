# NetBird connection command execution

The [managed journal integration](netbird-execution-journal.md) supersedes the
legacy wire subscriptions described below. Production connection commands use
expiring UUID-bound envelopes and permanent attempt/result evidence. Old raw
mutating subjects and profile steps return an explicit rejection. The managed
executor now also accepts version-two registration envelopes after an explicit
`registration-state` capability check. Console registration and provider-peer
workflows are documented in the console repository. Unix installation and
uninstallation remain unavailable pending their remaining lifecycle integration.
The journal recognizes exact version-three installation commands, but its
production executor rejects new ones before admission while no native installer
runner is configured.

Registration, connection, disconnection and profile selection share one command
implementation across Linux, macOS and Windows. This is an agent execution
boundary; the linked managed journal now integrates durable console admission.
Provider-peer ownership is established separately by retained console evidence.

## Requests and arguments

The legacy `key`, `management_url` and `profile` JSON fields remain compatible.
Wire messages are limited to 16 KiB (including JSON escaping) and must contain one UTF-8 JSON object with
unique, exact field names and string values. Unknown fields, nulls, duplicate
keys, trailing values and fields belonging to another operation are rejected
before identity discovery, command execution or inventory collection. The
profile-switch subscription now returns the same neutral rejection as the other
subscriptions, instead of leaving malformed requests unanswered.

Management URLs use the shared HTTPS base validator, with a 2,048-byte bound.
Registration keys are nonempty and at most 512 bytes; profile handles are nonempty
and at most 256 bytes. Both reject invalid UTF-8, control characters and leading
or trailing whitespace. A profile handle is one positional argument after `--`,
so even a handle beginning with `-` cannot add a flag. Spaces, quotes and shell
metacharacters remain literal data.

All four operations invoke the fixed installation binary directly:

| Platform | Binary |
| --- | --- |
| Linux | `/usr/bin/netbird` |
| macOS | `/usr/local/bin/netbird` |
| Windows | `C:\Program Files\NetBird\netbird.exe` |

The service PATH cannot select a replacement executable. An installation at a
different path must be integrated explicitly. No operation constructs a shell
command. Registration runs `down` before `up`; profile selection runs `profile
select` before `up`. A failed or canceled step prevents subsequent steps, and no
changing command is retried automatically.

Registration supplies its one-off key only through the `NB_SETUP_KEY` environment
of the `up` child. It is absent from argv and the preceding `down` child. Inherited
`NB_*` variables are removed, including case variants, before adding the explicit
operation environment: NetBird gives environment variables precedence over flags.
Child stdout/stderr are discarded without buffering or logging. Errors returned
to the console never contain child output or the registration key. The
[official CLI reference](https://docs.netbird.io/get-started/cli) documents the
environment-variable convention and precedence; the
[profile reference](https://docs.netbird.io/client/profiles) documents literal
profile handles and ambiguous-name rejection.

Environment delivery avoids argv disclosure; it does not conceal a credential
from a privileged local process or from the target user who owns that process.
Only a one-off registration key, never the provider access token, is delivered.

## Identity and cancellation

One command session resolves and retains the execution identity for the complete
sequence. Unix discovery invokes `/usr/bin/who` directly with a five-second
deadline and a 64 KiB output bound. Linux recognizes `seat0` and `:0`; macOS
recognizes `console`. Display-manager accounts are excluded. The selected user's
UID/GID and home environment are applied directly without a login shell or sudo.
User lookup errors and ambiguous desktop sessions fail closed. With no desktop
session, commands retain the service identity.

Windows enumerates local processes using the native snapshot API and retains the
single explorer process token and its native user environment. Multiple explorer processes are ambiguous and
require a single desktop session before retrying. Enumeration/token errors do
not fall back to the service identity. With no explorer process, commands use the
service identity. Snapshot, process and token handles are closed.

The subprocess sequence shares a one-minute deadline, or two minutes for profile
selection, including session discovery. Unix cancellation kills the owned process
group. Windows cancellation kills the directly invoked CLI process. Streams use
the null device, so there is no unbounded pipe drain or output allocation. Unix
account lookup uses the OS account service and has no separately enforced timeout.
Neither cancellation nor a successful CLI exit establishes rollback of work
already delegated to the independent NetBird daemon. Failures are reported as
unconfirmed and instruct the operator to refresh before retrying.

## Verification and remaining work

Owned process tests exercise literal arguments, inherited-variable removal,
per-child key delivery, large private output, failure and cancellation without
running a real NetBird executable. Command tests cover incompatible fields,
malformed and duplicate JSON, HTTPS validation, flag-like profile names, strict
step order and failure/cancellation barriers. Owned NATS tests execute the actual
four subscriptions and verify neutral rejection replies before any local action.
The Linux, macOS and Windows CI package lists include these suites.

Local race suites for `commands/report`, `commands/netbird`, `commands/runtime`
and the complete `agent` package passed on macOS in 1.796/1.540/4.586/24.891 seconds
and on isolated Linux in 1.026/1.019/4.402/28.102 seconds. Full Linux arm64, macOS
arm64 and Windows amd64 builds passed. The report and runtime Windows test
packages also cross-compiled; native execution remains a CI/Windows acceptance
check.

The post-command collector now shares the retained session and original deadline;
see [bounded NetBird observations](netbird-observations.md). Broker connection
commands and explicit refresh also inherit the agent service context. Failed
observations carry a neutral error, and current console/worker writers preserve
previously confirmed data. Unix installation/uninstallation still uses remote
shell scripts and needs release trust and cancellation work. Windows
installation/uninstallation uses the existing bounded package adapter.

Durable UUID-bound connection requests, current console authorization/source
locks, agent execution journals and immutable attempt/outcome history are now
implemented, together with coordinated console resolution of uncertain mutations;
see the linked journal contract for the current flow. Version-two registration
shares this permanent journal, binds the one-off key into the command digest, and
retains no key material in local records. Still required: console registration
workflow integration, trusted installation, and authoritative provider-peer association.
An agent-reported IP or hostname is not proof of provider ownership. Real NetBird
daemon, interactive desktop, Windows native process and physical-device acceptance
must be recorded separately from these owned fixtures and cross-compilation.
