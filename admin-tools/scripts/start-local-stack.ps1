param(
    [string]$RelayId = "relay-local",
    [string]$RelayHost = "127.0.0.1",
    [int]$RelayPort = 8443,
    [int]$KtLogPort = 8081,
    [int]$WitnessPort = 8082,
    [switch]$StartClient,
    [string]$ClientName = "alice",
    [string]$RoomId = "lobby"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$runtimeDir = Join-Path $repoRoot ".local"
$logsDir = Join-Path $runtimeDir "logs"
$goCacheDir = Join-Path $runtimeDir "go-build-cache"
$stateFile = Join-Path $runtimeDir "local-stack-pids.json"

New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
New-Item -ItemType Directory -Force -Path $logsDir | Out-Null
New-Item -ItemType Directory -Force -Path $goCacheDir | Out-Null

function Start-ServiceWindow {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Workdir,
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $logFile = Join-Path $logsDir "$Name.log"
    $launcher = @"
Set-Location '$Workdir'
$Command *>> '$logFile'
"@

    $process = Start-Process powershell `
        -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $launcher `
        -WorkingDirectory $Workdir `
        -PassThru

    [pscustomobject]@{
        name = $Name
        pid = $process.Id
        log = $logFile
    }
}

$services = @()

$services += Start-ServiceWindow `
    -Name "kt-log" `
    -Workdir (Join-Path $repoRoot "kt-log") `
    -Command @"
`$env:GOCACHE='$goCacheDir'
go run .\cmd\ktlog
"@

$services += Start-ServiceWindow `
    -Name "witness" `
    -Workdir (Join-Path $repoRoot "witness") `
    -Command @"
`$env:GOCACHE='$goCacheDir'
go run .\cmd\witness
"@

$relayCommand = @"
`$env:GOCACHE='$goCacheDir'
`$env:KT_LOG_URL='http://$RelayHost`:$KtLogPort'
`$env:WITNESS_URL='http://$RelayHost`:$WitnessPort'
`$env:RELAY_ID='$RelayId'
`$env:ADDR=':$RelayPort'
go run .\cmd\relay
"@

$services += Start-ServiceWindow `
    -Name "relay" `
    -Workdir (Join-Path $repoRoot "relay") `
    -Command $relayCommand

if ($StartClient) {
    $clientCommand = @"
if (-not (Test-Path '.\.venv\Scripts\Activate.ps1')) {
    Write-Host 'Missing client-tui virtual environment at .venv' -ForegroundColor Yellow
    Write-Host 'Create it later with: python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt'
}
if (Test-Path '.\.venv\Scripts\Activate.ps1') {
    . .\.venv\Scripts\Activate.ps1
}
`$env:RELAY_WS_URL='ws://$RelayHost`:$RelayPort/ws'
`$env:CHAT_ROOM='$RoomId'
`$env:CHAT_NAME='$ClientName'
python .\app\main.py
"@

    $services += Start-ServiceWindow `
        -Name "client-tui-$ClientName" `
        -Workdir (Join-Path $repoRoot "client-tui") `
        -Command $clientCommand
}

$services | ConvertTo-Json | Set-Content -Encoding UTF8 $stateFile

Write-Host "Local stack launched." -ForegroundColor Green
Write-Host "State file: $stateFile"
Write-Host "Logs:"
foreach ($service in $services) {
    Write-Host " - $($service.name) pid=$($service.pid) log=$($service.log)"
}
Write-Host ""
Write-Host "Health checks:"
Write-Host " - relay:   http://$RelayHost`:$RelayPort/healthz"
Write-Host " - kt-log:  http://$RelayHost`:$KtLogPort/healthz"
Write-Host " - witness: http://$RelayHost`:$WitnessPort/healthz"
