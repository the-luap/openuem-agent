#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
module_cache=$(go env GOMODCACHE)
signature_test_dir=$(mktemp -d)
signature_test_image="openuem-linux-package-signature-test:$(basename "$signature_test_dir")"
cleanup_signature_fixture() {
  if [[ -f "$signature_test_dir/container-id" ]]; then
    signature_test_container=$(cat "$signature_test_dir/container-id")
    if [[ "$signature_test_container" =~ ^[0-9a-f]{64}$ ]]; then
      docker rm --force "$signature_test_container" >/dev/null 2>&1 || true
    fi
  fi
  docker image rm "$signature_test_image" >/dev/null 2>&1 || true
  rm -rf "$signature_test_dir"
}
trap cleanup_signature_fixture EXIT
docker build -t "$signature_test_image" "$repository/scripts/fixtures/linux-package-signatures"
docker run --rm --init --cidfile "$signature_test_dir/container-id" --network none --read-only \
  --tmpfs /fixture:mode=0700,exec --tmpfs /etc/openuem/package-signing:mode=0700 \
  --tmpfs /tmp:mode=1777,noexec,nosuid,nodev \
  -v "$repository:/src:ro" -v "$module_cache:/go/pkg/mod:ro" -w /src \
  -e TMPDIR=/fixture -e GOCACHE=/fixture/cache -e GOWORK=off \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
  -e OPENUEM_TEST_LINUX_PACKAGE_SIGNATURES=owned-isolated-publishers \
  "$signature_test_image" sh -eu -c '
    sh scripts/fixtures/linux-package-signatures/build-fixtures.sh
    result=0
    go test -race -json -count=1 -timeout=5m ./internal/packagesignature > /fixture/results.json || result=$?
    cat /fixture/results.json
    [ "$result" -eq 0 ]
    for test in TestLinuxPackageSignaturesRequireAuthorizedNativePublisher TestLinuxPackageSignaturesRejectChangedTrustAndBytes TestLinuxPackageSignaturesRejectUnsafePrerequisites TestLinuxPackageSignatureCancellationJoinsProcess TestLinuxPackageSignatureLeaderExitTerminatesDescendant TestLinuxPackageSignatureNativeProcessOutputBounds; do
      grep -Eq "\"Action\":\"pass\".*\"Test\":\"$test\"" /fixture/results.json
    done
  '
