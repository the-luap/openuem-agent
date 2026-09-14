# Protected Linux service enablement

The internal enablement owner observes only
`/etc/systemd/system/multi-user.target.wants/openuem-agent.service`. Its literal
absolute target must be `/etc/systemd/system/openuem-agent.service`. A manager's
`UnitFileState=enabled` property alone does not establish this filesystem contract.

The observer retains every protected root-owned ancestor, the optional wants
directory and an `O_PATH|O_NOFOLLOW` descriptor for the link itself. It reads the
held symlink through `readlinkat(fd, "", ...)` without resolving its target. Only
a root-owned, single-linked symlink with the exact target is admitted. The target
unit's protected contents and effective manager state require separate owners.

Foreign/relative/extended targets, hard links, aliases, foreign ownership,
writable or special-mode directories, and regular files, directories or FIFOs in
the link slot fail. Inspection creates no directories or links. Once a directory
or link is acquired, removal or replacement fails even if the new link has the
same text. All descriptor and namespace checks repeat around the bounded read.

After actual manager enablement, `flush` requires an admitted link, syncs the
wants directory and its protected parent, then verifies the link again. It does
not repair a conflict. Cancellation is checked before and after the operation.
Close serializes with active inspections and releases descriptors only; retry
can reopen a retained canonical link.

The native race suite requires tests for absence without mutation, late link
creation, durable observation/retry, foreign metadata and targets, replaced
ancestry and links, cancellation and concurrent close. The complete suite,
including the authentication-consumption regression, passes in 7.740 seconds.

The [live systemd fixture](linux-systemd-definition.md) also publishes its owned
canonical unit, calls `EnableUnitFiles` with persistent mode and `force=false`,
checks the actual manager-created link, flushes it, reloads and verifies enabled
but inactive state with no process. Cleanup removes only the admitted fixture
link and definition inside the RAM-only guest. No agent is started by this test.

The [Linux activation command](native-linux-activation.md) joins these
file/manager observations with configuration admission, registration, startup
and authenticated readiness. Its additional live families exercise that sequence
against the owned system manager.

Descriptor-relative symlink reading follows Linux's
[readlinkat interface](https://man7.org/linux/man-pages/man2/readlink.2.html).
