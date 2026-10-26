@echo off
cd /d "%~dp0deploy\compose"
findstr /C:"AICP_GW_MODE=enforce" .env >nul && (set NEWMODE=monitor) || (set NEWMODE=enforce)
powershell -NoProfile -Command "(Get-Content .env) -replace '^AICP_GW_MODE=.*', 'AICP_GW_MODE=%NEWMODE%' | Set-Content .env"
echo Gateway mode is now: %NEWMODE%
echo Restarting the gateway container to apply...
docker compose up -d --no-deps gateway
echo.
echo Done. Run try-gateway.cmd to see the difference.
pause
