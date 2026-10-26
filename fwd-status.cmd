@echo off
cd /d "%~dp0deploy\compose"
echo === forwarder log (last 5 lines) ===
docker compose logs --tail 5 forwarder
echo.
echo === records shipped to the file output ===
docker compose exec forwarder sh -c "wc -l /state/aicp-forwarded.jsonl; cat /state/forwarder.checkpoint.json; echo; tail -n 1 /state/aicp-forwarded.jsonl | cut -c1-300"
pause
