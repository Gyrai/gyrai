Set-Location -Path (Join-Path $PSScriptRoot "deploy\compose")
docker compose --profile demo down
Read-Host "Stopped. Press Enter to close"
