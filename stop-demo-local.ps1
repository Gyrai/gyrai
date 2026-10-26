Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*uvicorn*" -or $_.Name -eq "opa.exe" } | ForEach-Object { Write-Host "stopping $($_.ProcessId) $($_.Name)"; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like "AICP *" } | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "Stopped."; Start-Sleep 3
