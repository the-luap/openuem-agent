# Protected Linux service definition publication

The internal `linuxservice` unit owner reads or publishes only the fixed
`/etc/systemd/system/openuem-agent.service` definition. It requires an already
existing protected directory; it does not create system directories, adopt a
legacy service or change existing permissions. The admitted running executable
and identity directory determine the complete [canonical unit](linux-service-unit.md).

All root-owned ancestors are retained with no-follow descriptors. The unit must
be a root-owned, single-linked regular file with mode 0600 or 0644 and at most
32 KiB. Reads bind its entire canonical text, immutable metadata and current
namespace before and after copying. Once acquired, even a byte-identical inode
replacement is rejected by that owner. Extra directives, different identity
arguments, aliases, hard links, special modes, writable files and nonregular
objects are conflicts. FIFOs cannot block inspection.

Publication creates a unique private temporary file in the retained directory,
writes the complete unit, sets mode 0644 and flushes it. A descriptor-relative
`renameat2(RENAME_NOREPLACE)` publishes it without replacing a concurrent winner.
The parent is synchronized and the published inode is rechecked. An exact
concurrent winner is admitted only through the same protected read path; that
observer also synchronizes the parent. Unknown definitions are preserved.

Successful retries do not rewrite the file. A pre-canceled operation creates
no unit, and cancellation after publication leaves the completed unit
available for a later admitted retry. Close releases descriptors without removing
the installed unit. Temporary cleanup checks the original inode and protected
namespace and does not remove unknown replacements.

The full native unit/connection/publication race suite passes in 7.299 seconds in
the owned read-only, network-isolated Linux fixture. Required publication tests
cover retained retries, foreign text and filesystem metadata, replaced namespaces,
cancellation and twelve competing publishers with exactly one complete inode and
no leftover temporary files. Linux Vet also passes.

This filesystem primitive does not reload, enable or start a service. The
[Linux activation command](native-linux-activation.md) now joins it with
effective systemd state and drop-in admission, protected agent configuration,
registration/startup and authenticated readiness.
