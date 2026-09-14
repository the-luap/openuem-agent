# Native NetBird runtime ownership inspection

The private removal observer now combines [protected package files](netbird-removal-ownership.md),
the loaded system launchd job and exact running NetBird processes into the shared
source-free removal descriptor. The service does not expose this observer yet:
the native execution owner and verified removal outcome must be connected before
advertising support. No process or job is stopped by this implementation.

## Exact running process identity

A bounded process enumeration identifies candidates by the two fixed executable
paths inside `/Applications/NetBird.app`. Process names are never ownership proof.
The native adapter obtains a task name port and reads the kernel's complete audit
token. It resolves the executable through that token, not through a reused PID.
The token, including its process generation, remains equal before and after code
validation; creation time and executable path are retained in the private proof.

`SecCodeCopyGuestWithAttributes` selects the dynamic guest using the audit token.
`SecCodeCheckValidity` requires strict validation and the exact NetBird signing
identifier, Apple Developer ID constraints and team `TA739QLA7A`. It also checks
consistency between the running guest and its static CodeDirectory. Merely finding
a signed file at the process's former path cannot establish ownership. The adapter
requires the valid dynamic status bit, rejects debugged guests and retains the
code's unique hash. Network access is disabled for this local process validation;
it is not a new online revocation or notarization assessment.

Two complete process scans must agree, irrespective of enumeration order. The
scan admits at most 8,192 candidate PIDs and 128 matching processes, requires the
system launch process in the enumeration and uses a ten-second parent deadline.
Inaccessible or incomplete evidence is unavailable. A matched process that exits
during capture cannot become successful ownership evidence. Cancellation joins a
native callback before returning. Empty process evidence alone is never package
absence. Native process support requires Darwin with CGO, root and macOS 11.3 or
later; other builds keep the native capability unavailable.

## Loaded system job

The native adapter enumerates the explicit system launchd domain and validates
the typed job collection, bounded size and unique labels before selecting
`netbird`. A successful enumeration without that label establishes an unloaded
job; a missing API, failed query, empty/partial collection or malformed result is
unavailable. A loaded job without a PID remains loaded, rather than absent.

The adapter copies only stable ownership fields: label, program, arguments,
environment, user, root/working directories and PID. Other jobs, private unrelated
fields and volatile launchd counters are not exported. The strict bounded plist
parser requires the fixed NetBird program and `service run` prefix, supported
root settings, typed arguments and environment, and a canonical PID when present.
The private configuration hash binds those loaded settings without exposing them.

Apple deprecates `SMCopyAllJobDictionaries` and provides no general replacement
for this read-only query. Its symbol is resolved at runtime; absence or an
unsupported result cannot become readiness. This implementation uses the typed
system-domain query, with explicit failure behavior, instead of depending on
human-oriented `launchctl print` formatting.

## Combined reviewed state

Two rounds of file, loaded-job and process inspection must agree. A running
launchd PID must match the exact validated NetBird CLI process under root effective
and real UIDs. A UI process, foreign user, missing PID proof, changed package,
changed process generation or changed loaded settings invalidates the observation.
The complete native state digest combines these three private fingerprints and
the resulting descriptor retains the exact package version and architecture.
Private evidence refuses JSON and redacts ordinary and Go-syntax formatting.

The next execution owner must reconstruct this descriptor under the current
journal revision, retain native object ownership through mutation, stop only the
owned service and processes, remove reviewed package objects and verify absence.
Configuration, credentials, logs and provider peers remain outside package removal.
Missing package receipts still mean unavailable evidence, not confirmed absence.
The common journal's original uncertainty and explicit recovery remain unchanged.

## Verification

Owned native tests create and ad-hoc sign an inert helper, then inspect the actual
running process. They reject a changed audit generation, mismatched path, signing
identifier or publisher, an exited process and a replacement file at the old
executable path. The helper is joined and its owned files are cleaned up. Native
CoreFoundation fixtures verify typed job enumeration, duplicate labels, present/
absent distinctions, field selection and the strict loaded-job parser without
registering any host job. Combined tests cover mismatched file/job/process evidence
and repeated snapshot checks. Protocol executor and journal regressions still
reject unconfigured removal before admission.

Darwin race tests and the portable Linux ownership suite pass, as do Darwin,
Linux and Windows agent builds and the Darwin no-CGO package test build. The
loaded-job parser also has a bounded CI fuzz job. A read-only native availability
probe successfully enumerated the system job collection without printing any
job names, settings or credentials. No NetBird executable, installer or daemon
was run or removed; actual installed-device acceptance remains required.

## Primary references

- [Apple dynamic code validation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/Code.cpp)
- [Apple audit-token guest selection](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/SecCode.cpp)
- [Apple kernel audit-token query](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/task.c)
- [Apple audit-token process APIs](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c)
- [Apple system job enumeration](https://developer.apple.com/documentation/servicemanagement/smcopyalljobdictionaries(_:))
