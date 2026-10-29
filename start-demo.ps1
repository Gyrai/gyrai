# Gyrai — one-click demo start with Docker (Windows PowerShell)
$host.UI.RawUI.WindowTitle = "AICP docker launcher"
Set-Location -Path (Join-Path $PSScriptRoot "deploy\compose")

$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCmd) {
    $candidate = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    if (Test-Path $candidate) { $env:Path = "C:\Program Files\Docker\Docker\resources\bin;" + $env:Path; $dockerCmd = Get-Command docker }
}
if (-not $dockerCmd) {
    Write-Host "Docker Desktop is not installed, or this window was opened before the install finished." -ForegroundColor Red
    Write-Host "If you just installed it: reboot (or sign out and back in), start Docker Desktop, then run this again."
    Read-Host "Press Enter to exit"; exit 1
}

Write-Host "Checking Docker engine..." -ForegroundColor Cyan
$engineOk = $false
for ($i = 0; $i -lt 30; $i++) {
    try { $null = & docker version --format '{{.Server.Version}}' 2>&1; if ($LASTEXITCODE -eq 0) { $engineOk = $true; break } } catch {}
    if ($i -eq 0) {
        Write-Host "Docker engine not responding. Starting Docker Desktop and waiting (up to ~3 minutes)..." -ForegroundColor Yellow
        $dd = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
        if (Test-Path $dd) { Start-Process $dd }
    }
    Start-Sleep 6
}
if (-not $engineOk) {
    Write-Host "Docker engine still not running. Open Docker Desktop, wait for the whale icon to settle (accept its terms if asked), then run this again." -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
}

if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }

Write-Host "Building and starting Gyrai (first run downloads images; several minutes)..." -ForegroundColor Cyan
& docker compose --profile demo up --build -d
if ($LASTEXITCODE -ne 0) { Read-Host "docker compose failed (see above). Press Enter to exit"; exit 1 }

Write-Host "Waiting for the console..." -ForegroundColor Cyan
$ok = $false
for ($i = 0; $i -lt 90; $i++) {
    try { Invoke-WebRequest -UseBasicParsing http://localhost:8000/healthz | Out-Null; $ok = $true; break } catch { Start-Sleep 2 }
}
if ($ok) {
    Write-Host ""
    Write-Host "RUNNING (Docker, policy engine ON)" -ForegroundColor Green
    Write-Host "  Console:  http://localhost:8000"
    Write-Host "  Gateway:  http://localhost:8080/v1   (key: gw-dev-key-alice)"
    Write-Host "  Mode:     see AICP_GW_MODE in deploy\compose\.env (monitor | enforce)"
    Write-Host "  Stop:     double-click stop-demo.cmd"
    Start-Process "http://localhost:8000"
} else {
    Write-Host "The console did not come up. Showing API logs:" -ForegroundColor Red
    & docker compose logs --tail 40 api
}
Read-Host "Press Enter to close this window (containers keep running)"
