#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
module_cache=$(go env GOMODCACHE)
enrollment_test_dir=$(mktemp -d)
enrollment_test_image="openuem-linux-enrollment-test:$(basename "$enrollment_test_dir")"
cleanup_enrollment_fixture() {
  if [[ -f "$enrollment_test_dir/container-id" ]]; then
    enrollment_test_container=$(cat "$enrollment_test_dir/container-id")
    if [[ "$enrollment_test_container" =~ ^[0-9a-f]{64}$ ]]; then
      docker rm --force "$enrollment_test_container" >/dev/null 2>&1 || true
    fi
  fi
  docker image rm "$enrollment_test_image" >/dev/null 2>&1 || true
  rm -rf "$enrollment_test_dir"
}
trap cleanup_enrollment_fixture EXIT
printf '%s\n' 1643d44b8d204f7087b2a3ec0fcb168d > "$enrollment_test_dir/machine-id"
docker build -t "$enrollment_test_image" "$repository/scripts/fixtures/linux-package-signatures"
docker run --rm --init --cidfile "$enrollment_test_dir/container-id" --network none --read-only \
  --tmpfs /fixture:mode=0700,exec --tmpfs /var/lib/systemd:mode=0700 \
  --tmpfs /etc/openuem/package-signing:mode=0700 --tmpfs /tmp:mode=1777,noexec,nosuid,nodev \
  -v "$enrollment_test_dir/machine-id:/etc/machine-id:ro" \
  -v "$repository:/src:ro" -v "$module_cache:/go/pkg/mod:ro" -w /src \
  -e TMPDIR=/fixture -e GOCACHE=/fixture/cache -e GOWORK=off \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
  -e OPENUEM_TEST_LINUX_ENROLLMENT=owned-isolated-enrollment \
  -e OPENUEM_TEST_LINUX_PACKAGE_SIGNATURES=owned-isolated-publishers \
  "$enrollment_test_image" sh -eu -c '
    systemd-creds setup >/dev/null 2>&1
    sh scripts/fixtures/linux-package-signatures/build-fixtures.sh
    result=0
    go test -race -json -count=1 -timeout=5m ./internal/enrollcommand > /fixture/results.json || result=$?
    cat /fixture/results.json
    [ "$result" -eq 0 ]
    for test in TestLinuxCommandWithNativeExecutablePackageAndProtectedEnrollment TestLinuxCommandRejectsNativeTrustAndBindingBeforeClaim TestLinuxCommandRecoversIssuedIdentityWithOriginalPendingKeys TestLinuxCommandRejectsUnsafeInputsAndStagingBeforeNetwork TestLinuxInputDirectoryRechecksRetainedAncestry; do
      grep -Eq "\"Action\":\"pass\".*\"Test\":\"$test\"" /fixture/results.json
    done
  '
