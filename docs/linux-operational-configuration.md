# Protected Linux operational configuration

The configuration owner fixes its paths to
`/etc/openuem-agent/openuem.ini` and
`/var/log/openuem-agent/openuem-agent.log`. It retains every existing ancestor
from the filesystem root without following links, requiring root ownership and
no group/other write access. The two operational directories must be private
root-owned directories with mode 0700. Missing directories are created only by
preparation after both namespaces have passed a read-only preflight.

The INI must be a root-owned, single-link regular file with mode 0600, bounded to
32 KiB. The activation provider supplies its existing enrollment-bound INI
validator: legacy configuration, another device's marker, conflicting duplicate
keys and unsupported settings are rejected. An existing log without a matching
INI also fails preflight. Logs are never read or truncated by activation; their
private ownership, regular-file type, single link and namespace are checked.

New configuration is written completely to a private temporary file, synchronized
and published with `renameat2(RENAME_NOREPLACE)`. File and parent directories are
synchronized before successful preparation. An admitted concurrent winner is
preserved. The retained INI descriptor rejects even byte-identical replacement;
valid administrator edits to the same file are admitted and preserved on retry.
Directory replacement, changed ancestry, foreign permissions or unknown log
objects fail without repair. Cancellation and close retain all published files.

The Linux activation provider joins this owner with the systemd controller. It
rechecks service ownership before configuration publication, verifies the INI
before and after registration, and checks configuration and registration around
the signed process-readiness call. It passes the protected device, tenant, site,
release, executable binding, expiry and public NKey to that controller. A failed
readiness check preserves the fact of already completed registration.

Native filesystem fixtures cover concurrent publication, modified settings,
foreign types/permissions/owners, symlinks, hardlinks, changed parents and
cancellation. `scripts/check-linux-activation.sh` additionally runs three required
provider families with the real INI parser and fixed production paths in private
container tmpfs mounts. Those tests inject the controller to inspect phase order,
readiness identity binding and changes between phases; the separate
[systemd fixture](linux-systemd-start.md) exercises the real manager and signed
readiness process.

The public Linux activation command remains gated pending the combined
actual-manager activation fixture and command dispatch integration. Production
publisher provisioning and physical installation/removal acceptance remain
separate work.
