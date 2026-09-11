param([ValidateSet('amd64', 'arm64')][string]$Architecture = 'amd64')
$ErrorActionPreference = 'Stop'
if ((go env GOOS) -ne 'windows' -or (go env GOARCH) -ne $Architecture) { throw 'Native fixture Go architecture differs from the required Windows target' }
$race = @()
if ($Architecture -eq 'amd64') { $race = @('-race') }
$events = go test @race -json -count=1 -timeout 2m -run '^Test(NativeWindowsSoftwareStaging|SoftwareStagingCleanup)' ./internal/windowssoftware
$result = $LASTEXITCODE
$events | Write-Output
if ($result -ne 0) { exit $result }
$records = $events | ForEach-Object { $_ | ConvertFrom-Json }
foreach ($test in @(
    'TestSoftwareStagingCleanupFailureRemainsPrivateAndClosed',
    'TestSoftwareStagingCleanupPreservesUnexpectedChildren',
    'TestNativeWindowsSoftwareStagingJoinsTransientCleanup',
    'TestNativeWindowsSoftwareStagingBoundsPermanentCleanupFailure',
    'TestNativeWindowsSoftwareStagingRechecksIdentityDuringCleanup',
    'TestNativeWindowsSoftwareStagingExcludesWriteDeleteAndReplacement',
    'TestNativeWindowsSoftwareStagingVerifiesActualAuthenticodeWithoutExecution/signed',
    'TestNativeWindowsSoftwareStagingVerifiesActualAuthenticodeWithoutExecution/changed_signature'
)) {
    if (-not ($records | Where-Object { $_.Test -eq $test -and $_.Action -eq 'pass' })) {
        throw "Required native staging test did not pass: $test"
    }
}
