$ErrorActionPreference = 'Stop'
$toolsDirectory = Join-Path $env:RUNNER_TEMP 'openuem-burn-execution-tools'
if (Test-Path $toolsDirectory) { throw 'The isolated Burn execution tool directory already exists' }
dotnet tool install wix --tool-path $toolsDirectory --version 4.0.6
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:OPENUEM_BURN_WIX = Join-Path $toolsDirectory 'wix.exe'
$env:OPENUEM_WINDOWS_BURN_FIXTURE = '1'
try {
    $events = go test -race -json -count=1 -timeout 7m -tags 'openuem_burn_test,openuem_msi_test' -run '^TestNativeWindowsSoftwareOwnedBurnInstallAndRemove$' ./internal/windowssoftware
    $result = $LASTEXITCODE
    $events | Write-Output
    if ($result -ne 0) { exit $result }
    $records = $events | ForEach-Object { $_ | ConvertFrom-Json }
    if (-not ($records | Where-Object { $_.Test -eq 'TestNativeWindowsSoftwareOwnedBurnInstallAndRemove' -and $_.Action -eq 'pass' })) {
        throw 'Required owned Burn installation and removal fixture did not pass'
    }
} finally {
    Remove-Item Env:OPENUEM_BURN_WIX -ErrorAction SilentlyContinue
    Remove-Item Env:OPENUEM_WINDOWS_BURN_FIXTURE -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $toolsDirectory -Recurse -Force
}
