#!/bin/sh
set -eu

# CI acceptance using only isolated temporary Unix sockets and generated keys.
# This binary contains no agent runtime, keychain backend or service registration.
GO_COMMAND=${GO_COMMAND:-go}
fixture_directory=$(mktemp -d /tmp/openuem-readiness-check.XXXXXX)
trap 'rm -rf -- "$fixture_directory"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$GO_COMMAND" test -c -race -o "$fixture_directory/readiness.test" ./internal/localready
sudo -n "$fixture_directory/readiness.test" -test.v -test.timeout=60s
