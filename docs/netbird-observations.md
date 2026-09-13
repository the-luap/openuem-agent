# Bounded NetBird observations

All three platforms use one collector for the fixed supported NetBird executable.
An absent executable produces a confirmed `Installed=false` observation. Other
file errors, unknown service states, invalid output and failed commands produce
the neutral `NetBird status could not be confirmed` error, never a fabricated
uninstalled or disconnected state.

## Execution and output

Standalone collection has one 30-second context for desktop discovery and every
CLI request. Collection after registration, connection, disconnection or profile
selection retains the existing command session and original action deadline, with
a maximum 30-second child observation budget. The actual NATS callbacks pass the
agent service context to connection actions and explicit refresh, so service
shutdown cancels those subprocesses. Scheduled inventory uses its own finite
collection deadline. Native filesystem/account/token operations retain the OS
limitations described in [command execution](netbird-command-execution.md).

The collector runs `version`, `service status`, `status --json` and `profile list`
directly. A stopped daemon returns confirmed stopped service state after the first
two calls, without inventing live connection or profile data. Current profile
tables receive one additional read-only `profile list --show-id` call. No changing
command or failed observation is automatically retried.

`CommandSession.Output` retains stdout while discarding stderr. Both streams count
toward a shared byte limit; exceeding it cancels the owned command. Limits are
4 KiB for version/service output, one MiB for status JSON and 256 KiB for profile
output. Failed, canceled, oversized and partially drained output is never returned
to the parser. The existing one-second pipe-drain bound applies. Inherited NetBird
environment overrides are removed; the collector sets `LC_ALL=C` and `LANG=C`.
The registration key is absent from every observation child's environment.

## Parsing and profile identities

Service output must identify exactly a running or stopped NetBird service.
Substring matches such as `not running` cannot establish a running state. Status
JSON must be one UTF-8 object without duplicate keys, case-alias duplicates or more
than 32 nested containers. Required connection/peer fields must have their actual
types. IP addresses/prefixes, URL credentials, counters, DNS entries and projected
text are validated and bounded. Irrelevant future fields remain compatible.
Projection succeeds as a whole; malformed data cannot partially update a report.

The parser supports the counted marker list in the
[NetBird 0.52 source](https://github.com/netbirdio/netbird/blob/v0.52.0/client/cmd/profile.go)
and the current name/ID tables documented in
[NetBird profiles](https://docs.netbird.io/client/profiles). Table column boundaries
preserve spaces, commas and Unicode labels. Current name-only tables are followed
by their ID table so duplicate labels remain independently selectable. Duplicate
handles, multiple active entries, invalid columns and more than 256 profiles fail
closed. Clients without a supported profile-list format produce unconfirmed
observations; they do not become absent installations.

Reports add optional `ProfileDetails` entries containing ID, name and active state.
The existing `Profiles` field remains a handle projection for older consumers.
Legacy name-based clients use the whole name as their handle. These are local,
agent-reported profile identities, not authoritative provider-peer associations.
Sequential CLI reads are observations, not an atomic snapshot against independent
desktop changes.

## Persistence and verification

Scheduled inventory emits an explicit neutral `Netbird.Error` on collection
failure. Current console and worker model writers reject such observations before
upsert, retaining previously confirmed data. They also reject invalid profile
identities and limit the database write to ten seconds. Structured profile state
uses the shared versioned codec; current console selectors display labels and
submit handles. Older consumers must be upgraded before relying on the failure
preservation contract.

Owned process tests exercise stdout/stderr isolation, a shared exact-size limit,
overflow on either stream, cancellation and rejection of partial output. Collector
tests cover both profile formats, duplicate names with distinct IDs, Unicode and
commas, unknown service states, malformed JSON, all read failure positions,
cancellation, confirmed executable absence and failure propagation into inventory.
The complete agent race suites and all three platform builds are checked; native
Windows execution and real NetBird daemon/desktop acceptance remain separate gates.

Still required: durable console/agent action admission and journals, immutable
attempt/outcome history, scope and source locks throughout execution, authoritative
provider-peer association, explicit uncertainty resolution, trusted Unix installers
and physical/provider acceptance. Legacy console pages may fall back to previously
saved data after a refresh failure; persistent observation-age/failure presentation
belongs to the unfinished command/history workflow.
