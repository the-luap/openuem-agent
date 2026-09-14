# Native Linux activation

The installed Linux agent handles `activate` before opening its logger or
starting service work. After [native enrollment](native-linux-enrollment.md), run
the enrolled installed executable as root with the same protected identity
directory:

```sh
sudo /path/to/installed/openuem-agent activate \
  -identity-directory /path/to/protected/identity
```

AMD64 and ARM64 are supported on systemd hosts. The command reopens the native
encrypted identity and release checkpoint, verifies platform and architecture,
and binds the current kernel-selected executable to the stored signed agent
size/hash. It accepts no invitation, server, service-name or trust override.
The existing systemd credential host key and protected installed paths remain
prerequisites; activation does not provision or replace them.

The [configuration owner](linux-operational-configuration.md) prepares
`/etc/openuem-agent/openuem.ini` and the private `/var/log/openuem-agent`
directory. The [registration controller](linux-systemd-registration.md) admits
and persistently enables only the canonical `openuem-agent.service`, running as
root with the enrolled executable and identity directory. Existing foreign units,
vendor definitions, aliases, drop-ins and incompatible configuration fail without
replacement. Compatible administrator settings and existing logs are retained.

The [start controller](linux-systemd-start.md) requires device-signed local
readiness from the exact main process observed by systemd. Successful JSON
contains `registered: true`, `running: true` and the retained device, tenant and
site IDs. If registration completes but readiness fails, the public result keeps
`registered: true` and `running: false`. Cancellation stops waiting and preserves
the registered service and identity; the process may continue starting. Inspect
the service error, correct its cause and retry the same command. Retrying an
admitted running service does not restart it or enroll another device.

Local readiness means service initialization. Verify remote connectivity and
inventory separately in the console. Final installer distribution, production
publisher provisioning, and physical installation/removal acceptance require
their own evidence.

## Verification

`scripts/check-linux-activation.sh` requires four native activation test families
with the actual fixed-path configuration owner and an injected controller. These
exercise phase order, retained settings, conflicting state, both architectures,
release/executable admission and public partial results. The script also builds
the actual Linux executable and requires `activate -help` to exit successfully
without creating configuration or log files.

`scripts/check-linux-systemd.sh` requires nine live families on each of three
fresh RAM-only virtual machines: seven manager families and two joined activation
families. The provider fixture exercises fresh activation, retained settings,
initialization timeout and foreign signed identity with the real system manager,
configuration owner and readiness socket. The command fixture enrolls once
through an owned loopback TLS issuer, persists encrypted records using real
`systemd-creds`, closes the issuer and reopens the store. It invokes public `Run`
and then `Handle` with no injected providers. The canonical unit launches the
same admitted test executable, which loads its actual encrypted identity and
signs readiness. Repeated activation preserves all encrypted records and scope.

The helper is restricted to the fixture's exact paths, root PID-1 manager,
synthetic marker, kernel marker and RAM filesystem. It models readiness, not
broker initialization or inventory delivery. The guest has loopback only, no
network device or host filesystem mounts. Test cleanup stops only its freshly
admitted canonical helper and joins shutdown before removing owned files.
The native enrollment suite separately verifies signed DEB/RPM and signed
bootstrap admission; this activation fixture starts from an explicitly authorized
test bootstrap and does not establish production signing trust.
