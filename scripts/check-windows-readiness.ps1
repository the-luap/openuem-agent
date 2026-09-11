param([ValidateSet('amd64', 'arm64')][string]$Architecture = 'amd64')
$ErrorActionPreference = 'Stop'
if ((go env GOOS) -ne 'windows' -or (go env GOARCH) -ne $Architecture) { throw 'Native fixture Go architecture differs from the required Windows target' }
$race = @()
if ($Architecture -eq 'amd64') { $race = @('-race') }
$events = go test @race -json -count=1 -timeout 2m -run '^TestNativeWindowsReadiness' ./internal/localready
$result = $LASTEXITCODE
$events | Write-Output
if ($result -ne 0) { exit $result }
$records = $events | ForEach-Object { $_ | ConvertFrom-Json }
$required = @(
    'TestNativeWindowsReadinessBindsIdentityPIDAndSingleton',
    'TestNativeWindowsReadinessShutdownJoinsBorrowedSignerAndIdleClients',
    'TestNativeWindowsReadinessRejectsChangedPermissionsAndPartialAddress',
    'TestNativeWindowsReadinessRecoversAfterProcessExit',
    'TestNativeWindowsReadinessListenerShutdownSurvivesDisconnectedClients/idle',
    'TestNativeWindowsReadinessListenerShutdownSurvivesDisconnectedClients/pending',
    'TestNativeWindowsReadinessListenerShutdownSurvivesDisconnectedClients/disconnected'
)
foreach ($test in $required) {
    if (-not ($records | Where-Object { $_.Test -eq $test -and $_.Action -eq 'pass' })) {
        throw "Required native readiness test did not pass: $test"
    }
}
