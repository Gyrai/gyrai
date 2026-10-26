@echo off
cd /d "%~dp0deploy\compose"
echo Sending four test prompts through the gateway...
docker compose cp ..\..\try-gateway.py gateway:/tmp/try-gateway.py >nul
docker compose exec -e AICP_TARGET=http://localhost:8080/v1 gateway python /tmp/try-gateway.py
echo.
pause
