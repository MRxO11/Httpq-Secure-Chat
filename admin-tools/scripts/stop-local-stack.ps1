param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$stateFile = Join-Path $repoRoot ".local\local-stack-pids.json"

if (-not (Test-Path $stateFile)) {
    Write-Host "No local stack state file found at $stateFile" -ForegroundColor Yellow
    exit 0
}

$services = Get-Content $stateFile -Raw | ConvertFrom-Json
foreach ($service in $services) {
    try {
        $process = Get-Process -Id $service.pid -ErrorAction Stop
        if ($Force) {
            Stop-Process -Id $process.Id -Force
        } else {
            Stop-Process -Id $process.Id
        }
        Write-Host "Stopped $($service.name) pid=$($service.pid)"
    } catch {
        Write-Host "Process already gone for $($service.name) pid=$($service.pid)" -ForegroundColor Yellow
    }
}

Remove-Item $stateFile -Force
Write-Host "Local stack state cleared."
