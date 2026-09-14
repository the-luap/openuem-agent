#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
module_cache=$(go env GOMODCACHE)
activation_test_dir=$(mktemp -d)
activation_test_image="openuem-linux-activation-test:$(basename "$activation_test_dir")"
cleanup_activation_fixture() {
  if [[ -f "$activation_test_dir/container-id" ]]; then
    activation_test_container=$(cat "$activation_test_dir/container-id")
    if [[ "$activation_test_container" =~ ^[0-9a-f]{64}$ ]]; then
      docker rm --force "$activation_test_container" >/dev/null 2>&1 || true
    fi
  fi
  docker image rm "$activation_test_image" >/dev/null 2>&1 || true
  rm -rf "$activation_test_dir"
}
trap cleanup_activation_fixture EXIT
docker build -t "$activation_test_image" "$repository/scripts/fixtures/linux-credentials"
docker run --rm --init --cidfile "$activation_test_dir/container-id" --network none --read-only \
  --tmpfs /fixture:mode=0700,exec --tmpfs /etc/openuem-agent:mode=0700,noexec,nosuid,nodev --tmpfs /var/log/openuem-agent:mode=0700,noexec,nosuid,nodev \
  --tmpfs /tmp:mode=1777,noexec,nosuid,nodev \
  -v "$repository:/src:ro" -v "$module_cache:/go/pkg/mod:ro" -w /src \
  -e TMPDIR=/fixture -e GOCACHE=/fixture/cache -e GOWORK=off \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
  -e OPENUEM_TEST_LINUX_ACTIVATION=owned-isolated-activation \
  "$activation_test_image" sh -eu -c '
    result=0
    go test -race -json -count=1 -timeout=2m ./internal/activatecommand > /fixture/results.json || result=$?
    cat /fixture/results.json
    [ "$result" -eq 0 ]
    for test in TestLinuxActivationUsesProtectedINIAndExactReadinessIdentity TestLinuxActivationRejectsChangedConfigurationBetweenPhases TestLinuxActivationPreflightPreservesForeignConfigurationAndLog; do
      grep -Eq "\"Action\":\"pass\".*\"Test\":\"$test\"" /fixture/results.json
    done
  '
