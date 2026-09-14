# Retained NetBird removal staging recovery

Interrupted [native removal](netbird-removal-execution.md) preserves its private
staging directory and prevents a fresh removal. Recovery must distinguish the
original manifest from current remaining files and from the original journal
outcome. Explicit journal release does not remove staging or authorize deletion
of unknown filesystem objects.

## Original manifest reader

The private schema-one manifest now has an explicit bounded codec and protected
reader. Its wire bytes remain identical to the original anonymous writer. The
codec binds the original request UUID and complete native removal descriptor,
limits bytes and object count, and validates the complete original path graph.
Required package/receipt nodes, parent directories, optional missing ancestors,
regular-file hashes, single links, the fixed CLI symlink target, trusted owners
and execution-compatible modes are checked before a new stage can be created.

Exact canonical-byte comparison rejects duplicate, aliased, missing, unknown and
null fields, trailing values and normalized number spellings. Incidental JSON and
formatting cannot expose private path, inode or ACL metadata. Only the explicit
writer can serialize a manifest to its protected local file.

The reader starts from protected root and Applications ancestry. It opens the
exact original UUID's stage with no symlink following, requires its owned 0700
directory and an owned single-link 0600 regular manifest, and bounds input before
reading. Both original ancestor bindings must still match the retained manifest.
First-pass descriptors remain open until ancestry, directory and file metadata
are reobserved, preventing immediate inode reuse. A private digest binds this
stable manifest evidence; it contains no private path or source data.

This reader is read-only. It does not inspect or delete remaining payloads, forget
receipts, stop processes, load services, release a journal or advertise recovery
capability. The separate remaining-file observer below consumes its evidence.
Missing or incomplete manifests remain unavailable to this reader.

## Current remaining-file observer

The private recovery file observer now joins the validated original manifest with
two complete current filesystem snapshots. It keeps the first manifest and object
descriptors open until comparison completes and binds the result to a separate
source-free digest. The exact selected stage must be the only removal-stage entry
in Applications. Unknown siblings, scaffold entries, payloads and source
replacements make observation unavailable.

Every existing source or staged payload must match the original object identity,
mode, owner, ACL, flags and content or fixed symlink target. A payload cannot exist
on both sides. A source app must still contain its complete original subtree;
the atomic root move cannot justify partial deletion at the source. A staged app
may contain a partial purge, including an empty original app directory. Only its
directory accounting may change; inode/mount/ownership/content checks remain.
The known moved/restored roots can have rename-induced ctime changes.

Scaffold directories are exact owned 0700 entries under protected ancestry. Empty
directories already removed by an interrupted final cleanup remain explicitly
missing. Native receipt files, if still present, must match the exact original
objects and hashes. Both present, both absent and partial receipt state remain
distinct; filesystem absence does not prove an OS receipt query or removal
completion. These observations never delete files or remove the original barrier.

## Current runtime and native receipt observer

The combined private observer now binds two complete rounds of current files,
native receipt state, typed system-job configuration and exact process instances.
First-round file descriptors stay open across both rounds. Any changed component
refuses a recovery fingerprint. The fingerprint binds the original request and
descriptor without exposing private paths, inode metadata or service settings.

Process inspection accepts only the original CLI/UI executable paths and their
two exact relocated paths under the canonical original request's stage. Complete
bounded process scans must agree on kernel audit token, generation, start time,
path and dynamically validated vendor code. Unrelated names, foreign stages and
path aliases never acquire process ownership. Fresh-removal process validation
continues to accept only the original two paths. Native inert-process tests
verify the same audit/code identity after an actual path relocation.

The fixed `system/netbird` job must retain an owned typed configuration. Its
original CLI link may already have moved, so configuration validation uses the
manifest's original link presence. Staged program aliases remain unavailable.
A loaded PID must match a proven CLI process with root effective and real users,
including an exact relocated process. A loaded job without a PID stays loaded.

Native receipt observation uses successful bounded `pkgutil --volume /
--pkgs-plist` output, with exact ID matching, a 512 KiB byte limit and at most
8,192 unique typed strings. The previous regexp absence query returns exit status
1 for an empty result on macOS; it cannot distinguish successful absence through
the existing strict process reader. The structured list returns a successful
empty array while preserving actual tool failures as errors.

Remaining receipt files must still match their original manifest objects. Native
list presence must agree with the surviving BOM. Complete receipts also require
the exact native package version and root volume; any surviving BOM must enumerate
the complete original payload paths, independently of a partial staged purge.
Native list presence repeats after these queries. Four states remain separate:

- `present`: both original receipt files, recognized native ID, exact metadata
  and original file list;
- `bom-only`: original BOM and recognized ID/file list, without an invented
  current package version;
- `plist-only`: original orphan plist and successful native ID absence;
- `absent`: neither receipt file and successful native ID absence.

An owned disposable-volume fixture verifies all four native listing behaviors
using a unique nonvendor package ID. Observing an orphan does not remove it or
claim completion. Explicit recovery commands and journal admission, native
continuation (including orphan receipt handling), and scoped console integration
remain open. Missing-manifest or wholly empty-stage recovery also needs a
separate explicit evidence policy. This observer advertises no recovery
capability and never releases the original journal barrier.

## Recovery runtime stop primitive

The private recovery runtime mutator now rechecks the exact reviewed typed job,
boots out only `system/netbird`, and confirms that it is unloaded before stopping
the reviewed processes. Each signal revalidates the canonical original request,
exact original/relocated executable path, kernel audit token and dynamically
validated vendor code. Signals use the audit token, never a PID fallback.

Only the bounded graceful-stop timeout can enable the fixed forced signal, which
revalidates the same proof again. Cancellation, changed code/path, inaccessible
runtime evidence and other errors cannot escalate. Completion requires a full
native scan with no original or selected-stage executable and an unloaded job.
This primitive is not published as a command or capability. Its caller still
needs explicit journal admission and an owner for the remaining filesystem work.

## Remaining staged-payload purge primitive

The private purge primitive now accepts a reviewed current-file snapshot only
after reinspection agrees exactly and every original source root is absent. Its
caller must supply complete runtime quiescence checks before and after purging.
Receipt files, the original manifest and the remaining scaffold are preserved;
this primitive alone does not complete recovery or clear retained staging.

Only remaining original staged payload objects are selected, deepest first.
Every parent directory is bound by its original current inode/device, mode,
owner, ACL and flags through descriptor-relative traversal. Directory accounting
can change as approved children disappear. Each leaf is hashed and compared,
its entire ancestry is re-resolved, and its opened inode/type is checked before
descriptor-relative unlink. Empty-directory removal preserves unknown children.
macOS opens CLI symlinks themselves with `O_SYMLINK`; Linux fixtures use
`O_PATH | O_NOFOLLOW`. Neither follows their target.

The final file inspection must show no source or staged payload, unchanged
receipts and the same original manifest. Changed/replaced files and parents,
unexpected entries, new source packages, receipt changes, cancellation and lost
quiescence retain remaining evidence and refuse completion. Already purged
payload and partially removed scaffolds are accepted without recreating them.

## Verification

An independent original-writer fixture verifies byte compatibility, including
optional absent files and entire optional ancestry. Codec fixtures reject invalid
ownership graphs and ambiguous JSON; writer refusal leaves no staging directory.
Owned filesystem checks cover stable repeated reads, unchanged source files and
manifest, protected modes, symlinks, hardlinks, oversized/empty/corrupt files,
foreign original references/descriptors, replaced parent directories and
cancellation. Reading evidence does not clear the existing removal barrier.

Remaining-file fixtures cover pre-move, app-only move, complete move, partial purge,
empty original app directory, full purge, partial/absent receipts and partial
scaffold cleanup. Negative fixtures preserve changed/incomplete source trees,
changed/replaced/added staged payloads, unsafe modes, extra scaffold entries,
symlinked scaffolds, replaced receipts, duplicated source roots, foreign stages
and missing manifests. Repeated stable inspection keeps the same fingerprint.

Combined fixtures cover original and relocated loaded daemons, loaded waiting
jobs, partial purge, and all receipt states. Changed files, source/receipt
replacements, foreign original references/descriptors, changing audit generations,
unavailable processes, wrong daemon users, UI-as-daemon, staged job programs,
inconsistent native lists, wrong metadata/file lists and cancellation refuse
evidence while preserving staging. Typed-list fixtures reject truncation,
duplicate/invalid entries, namespaces, external DTDs, trailing documents and
native failures, and accept a complete 8,192-entry inventory.

Runtime-stop fixtures verify exact callback proofs/order, graceful exit,
timeout-only force, current job drift, foreign/duplicate process evidence,
nonroot daemons, failed bootout/signal/quiet checks, cancellation and a process
appearing in the final complete scan. Invalid evidence reaches no native mutator.

Purge fixtures cover complete and partial remaining payload, already purged trees
and partial scaffolds. Replacement-parent tests retain the original nested file
inodes and bytes beneath an unreviewed parent, which still prevents deletion.
Other negative fixtures preserve changed leaves, unknown children, replacement
sources and receipts, and retain the manifest on every failure.

macOS races and the owned Linux ARM64 filesystem fixture pass. Full native
installation/removal, journal and command-service races remain successful, as do
Darwin CGO, Linux and Windows agent builds and Darwin without-CGO package
compilation. Fixtures do not read or change host NetBird state. Actual interrupted
package/reboot/desktop acceptance remains separate.
