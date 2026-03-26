param(
    [string]$OutputPath = ".\\relay-identity-placeholder.txt"
)

"Replace this placeholder with real offline relay key generation tooling." |
    Set-Content -Path $OutputPath

Write-Host "Wrote placeholder artifact to $OutputPath"
