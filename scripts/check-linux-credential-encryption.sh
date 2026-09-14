#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
module_cache=$(go env GOMODCACHE)
credential_test_dir=$(mktemp -d)
credential_test_image="openuem-linux-credential-test:$(basename "$credential_test_dir")"
cleanup_credential_fixture() {
  if [[ -f "$credential_test_dir/container-id" ]]; then
    credential_test_container=$(cat "$credential_test_dir/container-id")
    if [[ "$credential_test_container" =~ ^[0-9a-f]{64}$ ]]; then
      docker rm --force "$credential_test_container" >/dev/null 2>&1 || true
    fi
  fi
  docker image rm "$credential_test_image" >/dev/null 2>&1 || true
  rm -rf "$credential_test_dir"
}
trap cleanup_credential_fixture EXIT
printf '%s\n' 1643d44b8d204f7087b2a3ec0fcb168d > "$credential_test_dir/machine-id"
docker build -t "$credential_test_image" "$repository/scripts/fixtures/linux-credentials"
docker run --rm --cidfile "$credential_test_dir/container-id" --network none --read-only \
  --tmpfs /fixture:mode=0700,exec --tmpfs /var/lib/systemd:mode=0700 \
  -v "$credential_test_dir/machine-id:/etc/machine-id:ro" \
  -v "$repository:/src:ro" -v "$module_cache:/go/pkg/mod:ro" -w /src \
  -e TMPDIR=/fixture -e GOCACHE=/fixture/cache -e GOWORK=off \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
  -e OPENUEM_TEST_LINUX_CREDS=owned-isolated-host-key \
  "$credential_test_image" sh -eu -c '
    systemd-creds setup >/dev/null 2>&1
    go test -race ./internal/enrollmentstore -count=1 -timeout=8m
  '
