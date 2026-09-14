#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
module_cache=$(go env GOMODCACHE)
unit_test_dir=$(mktemp -d)
unit_test_image="openuem-linux-unit-test:$(basename "$unit_test_dir")"
cleanup_unit_fixture() {
  if [[ -f "$unit_test_dir/container-id" ]]; then
    unit_test_container=$(cat "$unit_test_dir/container-id")
    if [[ "$unit_test_container" =~ ^[0-9a-f]{64}$ ]]; then
      docker rm --force "$unit_test_container" >/dev/null 2>&1 || true
    fi
  fi
  docker image rm "$unit_test_image" >/dev/null 2>&1 || true
  rm -rf "$unit_test_dir"
}
trap cleanup_unit_fixture EXIT
docker build -t "$unit_test_image" "$repository/scripts/fixtures/linux-credentials"
docker run --rm --init --cidfile "$unit_test_dir/container-id" --network none --read-only \
  --tmpfs /fixture:mode=0700,exec --tmpfs /unprivileged:mode=1777,exec,nosuid,nodev \
  --tmpfs /tmp:mode=1777,noexec,nosuid,nodev \
  -v "$repository:/src:ro" -v "$module_cache:/go/pkg/mod:ro" -w /src \
  -e TMPDIR=/fixture -e GOCACHE=/fixture/cache -e GOWORK=off \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
  -e OPENUEM_TEST_LINUX_UNITS=owned-isolated-units \
  "$unit_test_image" sh -eu -c '
    go test -race -c -o /unprivileged/linuxservice.test ./internal/linuxservice
    result=0
    go test -race -json -count=1 -timeout=2m ./internal/linuxservice > /fixture/results.json || result=$?
    cat /fixture/results.json
    [ "$result" -eq 0 ]
    for test in TestLinuxUnitAcceptedByNativeSystemdParser TestLinuxManagerPrivateAuthenticationAndCalls TestLinuxManagerRejectsPIDBeforeAuthentication TestLinuxManagerRejectsUnsafeAndChangedNamespace TestLinuxManagerBoundsAuthenticationAndSanitizesErrors TestLinuxManagerCancellationAndJoinedClose TestLinuxManagerAuthenticatesKernelUID TestLinuxUnitFilePublicationAndRetainedRetry TestLinuxUnitFileRejectsForeignDefinitionsAndMetadata TestLinuxUnitFilePreservesChangedNamespaceAndCancellation TestLinuxUnitFileConcurrentExclusivePublication; do
      grep -Eq "\"Action\":\"pass\".*\"Test\":\"$test\"" /fixture/results.json
    done
  '
