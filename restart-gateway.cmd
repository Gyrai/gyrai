@echo off
cd /d "%~dp0deploy\compose"
findstr /C:"AICP_GW_MODE" .env
docker compose up -d --no-deps gateway
timeout /t 3 >nul
docker compose exec gateway python -c "import urllib.request,json;print(json.load(urllib.request.urlopen('http://localhost:8080/healthz')))"
pause
