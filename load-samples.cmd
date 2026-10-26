@echo off
cd /d "%~dp0deploy\compose"
echo Loading sample data into the control plane...
docker compose --profile demo run --rm --build seed
echo.
echo Done. Refresh http://localhost:8000
pause
