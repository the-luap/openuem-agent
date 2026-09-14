# Explicit current removal scaffold cleanup

The native package layer provides `InspectRemovalStageCleanup` and
`PrepareRemovalStageCleanup` for a distinct reviewed cleanup of a retained
private scaffold. This is a current filesystem operation, separate from
manifest continuation and read-only current absence verification. It never
claims that the original uninstall succeeded.

The native component does not itself prove a journal release or advertise a
remote capability. Its caller must first validate the exact original released
unconfirmed uninstall, bind current individual identity and ready-journal state,
obtain explicit operator confirmation and durably admit a new command before
running the acquired owner. The remote protocol, journal/service admission and
console cleanup lifecycle still need integration.

## Eligible current scope

The selected stage must be exactly
`Applications/.openuem-netbird-removal-<original-request-uuid>`. It must be the only
entry in the complete removal-stage namespace. Protected root and Applications
ancestry, the current directory identity and every child are observed through
retained directory descriptors without following symlinks.

Only the owned 0700 stage and these optional owned 0700 scaffold directories are
permitted: `Applications`, `usr`, `usr/local`, `usr/local/bin`, `Library` and
`Library/LaunchDaemons`. Every directory is enumerated with a bounded complete
listing. Missing scaffolds remain missing. Payloads, other names, symlinks,
unsafe modes or ownership, flags and changed ancestry prevent cleanup.

The only permitted regular file is the selected stage's `manifest.json`: owned,
single-link, mode 0600, at most 2 MiB and without a usable complete manifest. Its
entire current contents and identity contribute to the review fingerprint.
Missing, empty or incomplete metadata may be explicitly reviewed; no original
manifest or ownership graph is synthesized. Any complete usable manifest is
preserved for the separate manifest-continuation workflow, including one with
noncanonical encoding. Unknown files are never treated as incomplete metadata.

The supported package's app, CLI link, daemon plist and both receipt files must
be absent through their protected ancestors. Two complete native rounds require
an unloaded system job, no matching original or staged process and a successful
package list without the supported receipt ID. Each round is followed by an
unchanged complete filesystem snapshot. An unavailable query or late source,
receipt, stage or process refuses the review.

The public review contains only its state digest, the number of directories
(1–7), whether incomplete manifest metadata exists and its byte count. All four
values must match when preparing the owner. Private paths, inode and ACL details
and metadata contents cannot be serialized or incidentally formatted.

## Acquired operation

Preparation remains read-only and retains every observed existing object. The
single-use owner repeats the full current observation immediately before each
mutation. It removes only the reviewed empty scaffolds, deepest first, then the
exact incomplete metadata file, then the exact empty stage. Descriptor-relative
unlink and directory synchronization use the existing protected removal
primitive. Unknown children and replaced objects survive and stop progress.

The operation has no process-stop, package-removal, receipt-forget, service-start
or restoration callback. After deleting the stage it repeats the independent
complete current-absence check. A late failure can leave partial or finished
cleanup with an unconfirmed result; it grants no automatic retry, historical
success or journal release. A subsequent independently reviewed operation must
inspect the new current state. `Close` joins execution and closes descriptors,
without deleting anything by itself.

## Verification

Owned fixtures cover empty stages, missing/empty/incomplete manifests and partial
scaffolds; exact summaries, stable fingerprints and retained descriptors;
unknown children, retained payloads, foreign stages, hardlinks, symlinks,
oversized metadata, unsafe modes, complete manifests and replacement sources or
receipts. Drift tests preserve the original child inodes under replaced parent
ancestry, refuse changed metadata and summaries, and reject late process,
receipt and filesystem evidence. Partial-mutation and final-query failures
remain unconfirmed. Closing an interrupted owner waits for its run to join.

These tests use inert temporary files and injected native query results. They
perform no host NetBird operation and are not physical-device acceptance.

The final full native package race suite passed on macOS in 35.273 seconds.
The full native package suite passed in an isolated Linux container without
networking. The dedicated cleanup race selection passed in 2.877 seconds.
macOS CGO, Linux and Windows agent builds passed with the exported review and
acquisition APIs. The remote service does not yet advertise cleanup capability.
