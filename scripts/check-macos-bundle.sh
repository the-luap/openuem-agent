#!/bin/sh
set -eu

# Build-only acceptance. This never executes the agent, registers a service,
# installs a package or accesses a production identity/keychain.
GO_COMMAND=${GO_COMMAND:-go}
CGO_ENABLED=1
MACOSX_DEPLOYMENT_TARGET=13.0
CGO_CFLAGS="${CGO_CFLAGS:-} -mmacosx-version-min=13.0"
CGO_CXXFLAGS="${CGO_CXXFLAGS:-} -mmacosx-version-min=13.0"
CGO_LDFLAGS="${CGO_LDFLAGS:-} -mmacosx-version-min=13.0"
export CGO_ENABLED MACOSX_DEPLOYMENT_TARGET CGO_CFLAGS CGO_CXXFLAGS CGO_LDFLAGS
fixture_parent=${TMPDIR:-/tmp}
fixture_directory=$(mktemp -d "${fixture_parent%/}/openuem-macos-bundle-check.XXXXXX")
trap 'rm -rf -- "$fixture_directory"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 700 "$fixture_directory/output"

"$GO_COMMAND" build -o "$fixture_directory/openuem-agent" ./internal/service/mac
architecture=$("$GO_COMMAND" env GOARCH)
"$GO_COMMAND" run ./cmd/openuem-macos-bundle \
  -agent "$fixture_directory/openuem-agent" \
  -output "$fixture_directory/output" \
  -version 0.12.0 -build 42 -architecture "$architecture" \
  > "$fixture_directory/result.json"

bundle="$fixture_directory/output/OpenUEM Agent.app"
cmp "$fixture_directory/openuem-agent" "$bundle/Contents/MacOS/openuem-agent"
/usr/bin/plutil -lint -- "$bundle/Contents/Info.plist" \
  "$bundle/Contents/Library/LaunchDaemons/org.openuem.agent.daemon.plist"

# The test package exercises a native ad-hoc resource seal separately. This
# output has not received the release team's Developer ID/notarization approval.
cat "$fixture_directory/result.json"
