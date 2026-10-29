# AI Governance Plane — demo WITHOUT Docker. Uses the Python already on this PC.
# Starts: governance plane API (8000), mock model (9999), gateway (8080), and OPA (8181) if policies\opa.exe exists.
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root
$host.UI.RawUI.WindowTitle = "AICP launcher"

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { Write-Host "Python not found on PATH." -ForegroundColor Red; Read-Host "Press Enter"; exit 1 }

if (-not (Test-Path "$root\.venv")) {
    Write-Host "Creating Python environment (one time, ~1-2 minutes)..." -ForegroundColor Cyan
    & $py.Source -m venv "$root\.venv"
}
$venvPy = "$root\.venv\Scripts\python.exe"
& $venvPy -m pip install --quiet --disable-pip-version-check -r "$root\requirements-dev.txt" openai
if ($LASTEXITCODE -ne 0) { Read-Host "pip install failed. Press Enter"; exit 1 }

$opaExe = "$root\policies\opa.exe"
$opaOn = Test-Path $opaExe

function Launch($title, $dir, $envs, $cmd) {
    $pre = ($envs.GetEnumerator() | ForEach-Object { "`$env:$($_.Key)='$($_.Value)';" }) -join " "
    $script = "`$host.UI.RawUI.WindowTitle='$title'; Set-Location '$dir'; $pre & '$venvPy' $cmd"
    Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $script -WindowStyle Minimized
}

if ($opaOn) {
    Start-Process $opaExe -ArgumentList "run", "--server", "--addr", ":8181", "$root\policies" -WindowStyle Minimized
}

Launch "AICP api"     "$root\api"     @{ AICP_DATABASE_URL = "sqlite:///$($root -replace '\\','/')/aicp.db"; AICP_OPA_ENABLED = "$opaOn"; AICP_OPA_URL = "http://localhost:8181" } "-m uvicorn app.main:app --port 8000"
Launch "AICP mock"    "$root\gateway" @{} "-m uvicorn mock_upstream:app --port 9999"
Launch "AICP gateway" "$root\gateway" @{ PYTHONPATH = "$root\collectors"; AICP_GW_MODE = "monitor"; AICP_GW_UPSTREAM_URL = "http://localhost:9999"; AICP_GW_API_URL = "http://localhost:8000"; AICP_GW_OPA_ENABLED = "$opaOn"; AICP_GW_OPA_URL = "http://localhost:8181"; AICP_GW_KEYS_FILE = "$root\gateway\gateway_keys.json" } "-m uvicorn gw.main:app --port 8080"

Write-Host "Waiting for services..." -ForegroundColor Cyan
$ok = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        Invoke-WebRequest -UseBasicParsing http://localhost:8000/healthz | Out-Null
        Invoke-WebRequest -UseBasicParsing http://localhost:8080/healthz | Out-Null
        $ok = $true; break
    } catch { Start-Sleep 1 }
}
if (-not $ok) { Write-Host "Services did not start. Check the minimized 'AICP api' / 'AICP gateway' windows for errors." -ForegroundColor Red; Read-Host "Press Enter"; exit 1 }

Write-Host "Loading sample data..." -ForegroundColor Cyan
Set-Location "$root\collectors"
& $venvPy -m aicp_collectors.run file --path "$root\samples\sample-events.jsonl"
Set-Location $root

Write-Host "Sending four test prompts through the gateway..." -ForegroundColor Cyan
& $venvPy "$root\try-gateway.py"

Write-Host ""
Write-Host "RUNNING" -ForegroundColor Green
Write-Host "  Console:  http://localhost:8000"
Write-Host "  Gateway:  http://localhost:8080/v1   (key: gw-dev-key-alice)"
if (-not $opaOn) { Write-Host "  Policy engine: OFF (no policies\opa.exe). Events are recorded; advisory decisions show as 'allow'." -ForegroundColor Yellow }
Write-Host "  Stop:     double-click stop-demo-local.cmd"
Start-Process "http://localhost:8000"
Read-Host "Press Enter to close this window (services keep running)"
