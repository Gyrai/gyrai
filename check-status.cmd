@echo off
cd /d "%~dp0deploy\compose"
echo === Containers ===
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
echo.
echo === What is listening on port 8000 on this PC ===
netstat -ano | findstr ":8000 " | findstr LISTENING
echo.
echo === Stats as seen FROM THE HOST (what your browser sees) ===
curl -s http://localhost:8000/api/v1/events/stats
echo.
echo.
echo === Stats as seen INSIDE the Docker network ===
docker compose exec gateway python -c "import urllib.request;print(urllib.request.urlopen('http://api:8000/api/v1/events/stats').read().decode())"
echo.
pause
