#!/bin/sh
set -eu

# Root filesystem and native read-only framework acceptance in isolated fixtures.
# Tests inject identity stores and registration controllers; they never register
# a native daemon, start inventory or open a production identity/keychain.
GO_COMMAND=${GO_COMMAND:-go}
fixture_directory=$(mktemp -d /tmp/openuem-activation-check.XXXXXX)
trap 'rm -rf -- "$fixture_directory"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$GO_COMMAND" test -c -race -tags openuem_keychain_test -o "$fixture_directory/macservice.test" ./internal/macservice
"$GO_COMMAND" test -c -race -tags openuem_keychain_test -o "$fixture_directory/activation.test" ./internal/activatecommand
sudo -n "$fixture_directory/macservice.test" -test.v -test.timeout=90s
sudo -n "$fixture_directory/activation.test" -test.v -test.timeout=90s
