# Run the control plane directly on the host (Docker Desktop must be running).
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $bind = if ($env:CYBERLAB_BIND_IP) { $env:CYBERLAB_BIND_IP } else { "127.0.0.1" }
    $port = if ($env:CYBERLAB_CONTROL_PORT) { $env:CYBERLAB_CONTROL_PORT } else { "8443" }
    $python = Join-Path $root ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) { $python = "python" }
    & $python -m uvicorn app.main:app --host $bind --port $port --reload
}
finally {
    Pop-Location
}
