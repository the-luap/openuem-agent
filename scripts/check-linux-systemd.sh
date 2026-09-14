#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
module_cache=$(go env GOMODCACHE)
systemd_test_dir=$(mktemp -d)
systemd_test_image="openuem-linux-systemd-test:$(basename "$systemd_test_dir")"
cleanup_systemd_fixture() {
  if [[ -f "$systemd_test_dir/container-id" ]]; then
    systemd_test_container=$(cat "$systemd_test_dir/container-id")
    if [[ "$systemd_test_container" =~ ^[0-9a-f]{64}$ ]]; then
      docker rm --force "$systemd_test_container" >/dev/null 2>&1 || true
    fi
  fi
  docker image rm "$systemd_test_image" >/dev/null 2>&1 || true
  rm -rf "$systemd_test_dir"
}
trap cleanup_systemd_fixture EXIT
docker build -t "$systemd_test_image" "$repository/scripts/fixtures/linux-systemd"
docker run --rm --init --cidfile "$systemd_test_dir/container-id" --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges --cpus 2 --memory 2g \
  --tmpfs /fixture:mode=0700,exec,size=1g \
  -v "$repository:/src:ro" -v "$module_cache:/go/pkg/mod:ro" -w /src \
  -e TMPDIR=/fixture -e GOCACHE=/fixture/cache -e GOWORK=off \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
  "$systemd_test_image" bash scripts/fixtures/linux-systemd/run-guest.sh
