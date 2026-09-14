#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
module_cache=$(go env GOMODCACHE)
executable_test_dir=$(mktemp -d)
cleanup_executable_fixture() {
  if [[ -f "$executable_test_dir/container-id" ]]; then
    executable_test_container=$(cat "$executable_test_dir/container-id")
    if [[ "$executable_test_container" =~ ^[0-9a-f]{64}$ ]]; then
      docker rm --force "$executable_test_container" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$executable_test_dir"
}
trap cleanup_executable_fixture EXIT
docker run --rm --init --cidfile "$executable_test_dir/container-id" --network none --read-only \
  --tmpfs /fixture:mode=0700,exec -v "$repository:/src:ro" \
  -v "$module_cache:/go/pkg/mod:ro" -w /src \
  -e TMPDIR=/fixture -e GOCACHE=/fixture/cache -e GOWORK=off \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
  -e OPENUEM_TEST_LINUX_EXECUTABLE=owned-isolated-image \
  golang:1.26.8-bookworm sh -eu -c '
    result=0
    go test -race -json -count=1 -timeout=5m ./internal/bootstrapinstall > /fixture/results.json || result=$?
    cat /fixture/results.json
    [ "$result" -eq 0 ]
    for test in TestRunningAgentOpensBeforeBootstrapAndChecksActualExecutableBytes TestLinuxRunningImageMatchesKernelIdentity TestLinuxExecutableRejectsUnsafeImages TestLinuxExecutableRejectsChangedImageAndAncestors; do
      grep -Eq "\"Action\":\"pass\".*\"Test\":\"$test\"" /fixture/results.json
    done
  '
