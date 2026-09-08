# Protected bootstrap package staging

`internal/bootstrapinstall.StagePackage` connects the independently verified
configuration, exact-origin native download and native installer-signature check.
It accepts only the running Windows/macOS target and architecture, an authorized
HTTPS client, a previously protected staging root and the latest durable release
checkpoint. It does not issue an identity, install software or start the service.
The native command, consent/origin authorization, trusted release-key provisioning
and installer/service activation still need to connect these components.

Each operation creates a new private `package-<UUID>` child directory. It creates
the signed artifact filename with exclusive private permissions before writing
any bytes. The native client downloads only the configuration's exact release
through verified HTTPS and checks size/hash and expiry. The staging writer is
synced and closed before native signature verification. A protected read-only
descriptor is retained, bound to the original file identity and used to verify
the bytes before and after the native check. A renamed/replaced path, changed
permissions, changed bytes, expired configuration/release or newer checkpoint
prevents acceptance. Windows excludes concurrent writers during WinTrust itself;
the staging parent must remain protected until installation/activation finishes.

Successful staging returns an owned `Package`. Call its `Verify` with the latest
configuration/checkpoint immediately before use. `Path` is usable only until
`Close`; it does not establish release authorization by itself. Close is serialized
with verification and concurrent close calls. It closes the descriptor first,
removes only the originally owned file when its identity still matches, then
removes the empty child directory. It never recursively removes unknown files or
an unexpected replacement. Such interference returns a generic cleanup error and
retains the unexpected entry for investigation. The staging root is retained.

Failed downloads or native verification clean up this operation's owned staging.
Caller cancellation is preserved; remote/native diagnostics remain private.
Process crashes or an I/O failure before a file's identity can be recorded may
leave a private incomplete staging directory. Automatic crash cleanup/resume and
installer transactions remain future integration work. No invitation, endpoint
seed, CA key or signing private key is written into a package directory.

Tests run actual TLS downloads with independently signed fixture configuration
and releases. They cover private file access before native verification, partial
streams, signature failure, modification during/after checking, cancellation,
checkpoint rollback, concurrent closure and preserving an unexpected replacement.
The exported production path rejects an unsigned fixture. Windows additionally
stages the licensed Go EV-signature fixture through the real native verifier and
checks cleanup. Test packages are never installed or executed.
