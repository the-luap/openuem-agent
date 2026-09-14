#!/usr/bin/env bash
set -euo pipefail

# Compile and run only owned native lease fixtures. No host root privileges,
# service configuration, network access or credential storage are used.
repository=$(cd "$(dirname "$0")/.." && pwd)
module_cache=$(go env GOMODCACHE)
docker run --rm --network none --read-only \
  --tmpfs /fixture:mode=0700,exec --tmpfs /unprivileged:mode=1777,exec \
  -v "$repository:/src:ro" -v "$module_cache:/go/pkg/mod:ro" -w /src \
  -e TMPDIR=/fixture -e GOCACHE=/fixture/cache -e GOWORK=off \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
  golang:1.26.8-bookworm sh -eu -c '
    go test -race -c -o /unprivileged/service-lease.test ./internal/enrollmentstore
    /unprivileged/service-lease.test -test.v -test.count=1 -test.timeout=2m -test.run="^TestLinuxServiceLease(ProcessFixture|ExcludesProcessesAndSurvivesOwnerExit|RejectsUntrustedOrReplacedNativeObjects|RejectsUnsafeAncestryAndPreservesExistingData|InvalidatesChangedNamespaceWithoutUnlinkingEvidence|ConcurrentOwnersAndJoinedClose)$"
    test "$(id -u nobody)" = 65534
    runuser -u nobody -- env TMPDIR=/unprivileged /unprivileged/service-lease.test -test.v -test.count=1 -test.timeout=1m -test.run="^TestLinuxServiceLeaseRejectsUnprivilegedCaller$"
  '
