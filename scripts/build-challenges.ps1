# Build one image per challenges\<id>\ directory, plus the trusted relay image.
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    Write-Host "==> building cyberlab/forwarder:latest"
    docker build --pull -t "cyberlab/forwarder:latest" "infra/forwarder"
    if ($LASTEXITCODE -ne 0) { throw "docker build failed for infra/forwarder" }

    $found = 0
    Get-ChildItem -Path "challenges" -Directory | ForEach-Object {
        $yaml = Join-Path $_.FullName "challenge.yaml"
        if (-not (Test-Path $yaml)) { return }
        $image = "cyberlab/challenge-$($_.Name):latest"
        Write-Host "==> building $image"
        docker build --pull -t $image $_.FullName
        if ($LASTEXITCODE -ne 0) { throw "docker build failed for $($_.Name)" }
        $found++
    }
    if ($found -eq 0) { throw "No challenges found under challenges\" }
    Write-Host "Built $found challenge image(s) and the relay image."
}
finally {
    Pop-Location
}
