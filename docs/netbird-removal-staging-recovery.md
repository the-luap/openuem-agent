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

Current process/service ownership, native receipt-state interpretation, explicit
recovery commands and journal admission, native continuation and scoped console
integration remain open. An eligible file snapshot alone cannot authorize any of
those actions. Missing-manifest or wholly empty-stage recovery also needs a
separate explicit evidence policy.

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

macOS races and the owned Linux ARM64 filesystem fixture pass. Full native
installation/removal, journal and command-service races remain successful, as do
Darwin CGO, Linux and Windows agent builds and Darwin without-CGO package
compilation. Fixtures do not read or change host NetBird state. Actual interrupted
package/reboot/desktop acceptance remains separate.
