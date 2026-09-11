param([ValidateSet('amd64', 'arm64')][string]$Architecture = 'amd64')
$ErrorActionPreference = 'Stop'
if ((go env GOOS) -ne 'windows' -or (go env GOARCH) -ne $Architecture) { throw 'Native fixture Go architecture differs from the required Windows target' }
$race = @()
if ($Architecture -eq 'amd64') { $race = @('-race') }
$toolsDirectory = Join-Path $env:RUNNER_TEMP 'openuem-burn-format-tools'
if (Test-Path $toolsDirectory) { throw 'The isolated Burn tool directory already exists' }
dotnet tool install wix --tool-path $toolsDirectory --version 4.0.6
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:OPENUEM_BURN_WIX = Join-Path $toolsDirectory 'wix.exe'
try {
    $events = go test @race -json -p 1 -count=1 -timeout 7m -tags openuem_burn_test -run '^(TestOwnedWiXBundleLayout|TestNativeWindowsSoftwareOwnedBurnPreflight)$' ./internal/burnbundle ./internal/windowssoftware
    $result = $LASTEXITCODE
    $events | Write-Output
    if ($result -ne 0) { exit $result }
    $records = $events | ForEach-Object { $_ | ConvertFrom-Json }
    foreach ($test in @('TestOwnedWiXBundleLayout', 'TestOwnedWiXBundleLayout/386', 'TestOwnedWiXBundleLayout/amd64', 'TestOwnedWiXBundleLayout/arm64',
        'TestNativeWindowsSoftwareOwnedBurnPreflight', 'TestNativeWindowsSoftwareOwnedBurnPreflight/native_machine',
        'TestNativeWindowsSoftwareOwnedBurnPreflight/native_user', 'TestNativeWindowsSoftwareOwnedBurnPreflight/foreign_machine',
        'TestNativeWindowsSoftwareOwnedBurnPreflight/x86_machine')) {
        if (-not ($records | Where-Object { $_.Test -eq $test -and $_.Action -eq 'pass' })) {
            throw "Required generated Burn format fixture did not pass: $test"
        }
    }
} finally {
    Remove-Item Env:OPENUEM_BURN_WIX -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $toolsDirectory -Recurse -Force
}
