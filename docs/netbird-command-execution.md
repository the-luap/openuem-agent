# NetBird connection command execution

Registration, connection, disconnection and profile selection share one command
implementation across Linux, macOS and Windows. This is an agent execution
boundary; durable console admission and provider-peer ownership are separate,
unfinished parts of the NetBird lifecycle.

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

Local race suites for `commands/netbird`, `commands/runtime` and the complete
`agent` package passed on macOS in 1.404/2.693/26.860 seconds and on isolated Linux
in 1.017/2.182/26.752 seconds. Full Linux arm64, macOS arm64 and Windows amd64
builds passed. Both added Windows command test packages also cross-compiled;
their native execution remains a CI/Windows acceptance check.

The legacy inventory collector called after a successful sequence still has
unbounded subprocesses and an outdated textual profile-list parser. Consequently,
these changes do not claim an end-to-end deadline for the legacy synchronous
broker response. That collector needs a bounded, tested replacement before it is
used by durable command recovery. Unix installation/uninstallation still uses
remote shell scripts and needs release trust and cancellation work. Windows
installation/uninstallation uses the existing bounded package adapter.

Still required: durable UUID-bound requests, current console authorization/source
locks, agent execution journals, immutable attempt/outcome history, explicit
resolution of uncertain mutations, and authoritative provider-peer association.
An agent-reported IP or hostname is not proof of provider ownership. Real NetBird
daemon, interactive desktop, Windows native process and physical-device acceptance
must be recorded separately from these owned fixtures and cross-compilation.
