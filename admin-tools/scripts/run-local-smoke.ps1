param(
    [string]$RelayId = "relay-local",
    [string]$RelayHost = "127.0.0.1",
    [int]$RelayPort = 8443,
    [int]$KtLogPort = 8081,
    [int]$WitnessPort = 8082,
    [string]$RoomId = "smoke-room",
    [string]$RoomSecret = "smoke-secret",
    [int]$StartupTimeoutSeconds = 20,
    [switch]$SkipRelaySmoke,
    [switch]$SkipClientSmoke
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$checkScript = Join-Path $PSScriptRoot "check-local-stack.ps1"
$startScript = Join-Path $PSScriptRoot "start-local-stack.ps1"
$stopScript = Join-Path $PSScriptRoot "stop-local-stack.ps1"
$smokeScript = Join-Path $PSScriptRoot "relay_smoke.py"
$clientSmokeScript = Join-Path $PSScriptRoot "client_stack_smoke.py"
$venvPython = Join-Path $repoRoot "client-tui\.venv\Scripts\python.exe"
$pythonExe = if (Test-Path $venvPython) { $venvPython } else { "python" }

function Test-HealthStatus {
    param(
        [string]$Url
    )

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

function Wait-ForHealth {
    param(
        [string]$Name,
        [string]$Url,
        [datetime]$Deadline
    )

    while ((Get-Date) -lt $Deadline) {
        if (Test-HealthStatus -Url $Url) {
            Write-Host "[ok] $Name is healthy at $Url" -ForegroundColor Green
            return
        }
        Start-Sleep -Milliseconds 500
    }

    throw "$Name did not become healthy before timeout: $Url"
}

function Test-PythonDependency {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    & $pythonExe -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('$ModuleName') else 1)" *> $null
    return $LASTEXITCODE -eq 0
}

try {
    & $startScript `
        -RelayId $RelayId `
        -RelayHost $RelayHost `
        -RelayPort $RelayPort `
        -KtLogPort $KtLogPort `
        -WitnessPort $WitnessPort

    $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
    Wait-ForHealth -Name "kt-log" -Url "http://$RelayHost`:$KtLogPort/healthz" -Deadline $deadline
    Wait-ForHealth -Name "witness" -Url "http://$RelayHost`:$WitnessPort/healthz" -Deadline $deadline
    Wait-ForHealth -Name "relay" -Url "http://$RelayHost`:$RelayPort/healthz" -Deadline $deadline

    & $checkScript `
        -RelayHost $RelayHost `
        -RelayPort $RelayPort `
        -KtLogPort $KtLogPort `
        -WitnessPort $WitnessPort

    if (-not $SkipRelaySmoke) {
        if (-not (Test-PythonDependency -ModuleName "websockets")) {
            throw "Python dependency 'websockets' is missing. Create client-tui\.venv and install requirements.txt, or install websockets in the active Python environment."
        }
        Write-Host ""
        Write-Host "Running relay smoke test..." -ForegroundColor Cyan
        & $pythonExe $smokeScript --ws-url "ws://$RelayHost`:$RelayPort/ws" --room-id $RoomId
    }

    if (-not $SkipClientSmoke) {
        if (-not (Test-PythonDependency -ModuleName "websockets")) {
            throw "Python dependency 'websockets' is missing. Create client-tui\.venv and install requirements.txt, or install websockets in the active Python environment."
        }
        if (-not (Test-PythonDependency -ModuleName "cryptography")) {
            throw "Python dependency 'cryptography' is missing. Create client-tui\.venv and install requirements.txt, or install cryptography in the active Python environment."
        }
        Write-Host ""
        Write-Host "Running headless client-stack smoke test..." -ForegroundColor Cyan
        & $pythonExe $clientSmokeScript `
            --ws-url "ws://$RelayHost`:$RelayPort/ws" `
            --room-id "$RoomId-client" `
            --room-secret $RoomSecret
    }
} finally {
    & $stopScript
}
