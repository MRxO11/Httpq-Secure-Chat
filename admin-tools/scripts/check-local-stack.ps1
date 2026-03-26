param(
    [string]$RelayHost = "127.0.0.1",
    [int]$RelayPort = 8443,
    [int]$KtLogPort = 8081,
    [int]$WitnessPort = 8082
)

$ErrorActionPreference = "Stop"

function Test-HealthEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
        Write-Host "[ok]   $Name -> $Url ($($response.StatusCode))" -ForegroundColor Green
    } catch {
        Write-Host "[fail] $Name -> $Url ($($_.Exception.Message))" -ForegroundColor Red
    }
}

Test-HealthEndpoint -Name "relay" -Url "http://$RelayHost`:$RelayPort/healthz"
Test-HealthEndpoint -Name "kt-log" -Url "http://$RelayHost`:$KtLogPort/healthz"
Test-HealthEndpoint -Name "witness" -Url "http://$RelayHost`:$WitnessPort/healthz"
