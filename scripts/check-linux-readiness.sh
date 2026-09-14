#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
module_cache=$(go env GOMODCACHE)
readiness_test_dir=$(mktemp -d)
cleanup_readiness_fixture() {
  if [[ -f "$readiness_test_dir/container-id" ]]; then
    readiness_test_container=$(cat "$readiness_test_dir/container-id")
    if [[ "$readiness_test_container" =~ ^[0-9a-f]{64}$ ]]; then
      docker rm --force "$readiness_test_container" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$readiness_test_dir"
}
trap cleanup_readiness_fixture EXIT
docker run --rm --init --cidfile "$readiness_test_dir/container-id" --network none --read-only \
  --tmpfs /fixture:mode=0700,exec --tmpfs /unprivileged:mode=1777,exec \
  -v "$repository:/src:ro" -v "$module_cache:/go/pkg/mod:ro" -w /src \
  -e TMPDIR=/fixture -e GOCACHE=/fixture/cache -e GOWORK=off \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
  -e OPENUEM_TEST_LINUX_READINESS=owned-isolated-readiness \
  golang:1.26.8-bookworm sh -eu -c '
    go test -race -c -o /unprivileged/readiness.test ./internal/localready
    result=0
    go test -race -json -count=1 -timeout=3m ./internal/localready ./internal/agent ./internal/service/linux ./internal/service/lifecycle > /fixture/results.json || result=$?
    cat /fixture/results.json
    [ "$result" -eq 0 ]
    for test in TestLinuxReadinessTransitionsIdentityAndSingleton TestLinuxReadinessBindsObservedServiceProcess TestLinuxReadinessRejectsUnsafeOrChangedNamespace TestLinuxReadinessShutdownJoinsSigningAndDisconnectedClients TestLinuxReadinessRechecksAuthorityAfterSigning TestLinuxReadinessReclaimsOnlyInactiveOwnedSocket TestLinuxReadinessRejectsForeignPIDAndBoundsProbe TestLinuxReadinessAuthenticatesKernelRootPeer TestLinuxSchedulerPublishesNativeReadinessAfterInitialization; do
      grep -Eq "\"Action\":\"pass\".*\"Test\":\"$test\"" /fixture/results.json
    done
  '
