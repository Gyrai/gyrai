@echo off
cd /d "%~dp0deploy\compose"
echo Rebuilding and restarting the AI Control Plane with the latest code...
docker compose --profile demo up -d --build
echo.
echo Waiting for the console...
timeout /t 8 >nul
curl -s -o nul -w "console: HTTP %%{http_code} (302 = login page is up)\n" http://localhost:8000/
docker compose ps --format "table {{.Name}}\t{{.Status}}"
echo.
echo Open http://localhost:8000 and sign in (see deploy\compose\.env for AICP_ADMIN_PASSWORD).
pause
