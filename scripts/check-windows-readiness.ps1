$ErrorActionPreference = 'Stop'
$events = go test -race -json -count=1 -timeout 2m -run '^TestNativeWindowsReadiness' ./internal/localready
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
