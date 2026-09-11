param([ValidateSet('amd64', 'arm64')][string]$Architecture = 'amd64')
$ErrorActionPreference = 'Stop'
if ((go env GOOS) -ne 'windows' -or (go env GOARCH) -ne $Architecture) { throw 'Native fixture Go architecture differs from the required Windows target' }
$env:OPENUEM_WINDOWS_MSI_FIXTURE = '1'
try {
    $events = go test -json -p 1 -count=1 -timeout 3m -tags openuem_msi_test -run '^TestNativeWindowsSoftwareOwnedMSI' ./internal/commands/deploy ./internal/windowssoftware
    $result = $LASTEXITCODE
    $events | Write-Output
    if ($result -ne 0) { exit $result }
    $records = $events | ForEach-Object { $_ | ConvertFrom-Json }
    foreach ($test in @('TestNativeWindowsSoftwareOwnedMSIInstallPropertiesAndRemove',
        'TestNativeWindowsSoftwareOwnedMSIReadOnlyCompatibility',
        'TestNativeWindowsSoftwareOwnedMSIExecutorInstallAndRemove',
        'TestNativeWindowsSoftwareOwnedMSIMajorUpgrade')) {
        if (-not ($records | Where-Object { $_.Test -eq $test -and $_.Action -eq 'pass' })) {
            throw "Required owned MSI execution fixture did not pass: $test"
        }
    }
} finally {
    Remove-Item Env:OPENUEM_WINDOWS_MSI_FIXTURE -ErrorAction SilentlyContinue
}
