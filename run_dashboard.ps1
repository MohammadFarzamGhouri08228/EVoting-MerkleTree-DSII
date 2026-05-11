$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$mmrExe = Join-Path $root "mmr_sim.exe"
$webExe = Join-Path $root "evoteverify_web.exe"

if (-not (Test-Path $mmrExe)) {
    Write-Host "[*] Building mmr_sim.exe..."
    g++ -std=c++17 -O2 -I. -Isim -o mmr_sim.exe main_sim.cpp src/mmr_simulation.cpp src/merkle_mountain_range.cpp -lws2_32
}

if (-not (Test-Path $webExe)) {
    Write-Host "[*] Building evoteverify_web.exe..."
    g++ -std=c++17 -O2 -I. -o evoteverify_web.exe main.cpp src/ballot.cpp src/voter_registry.cpp src/merkle_tree.cpp src/live_visualization_server.cpp -lws2_32
}

$existing = Get-Process mmr_sim -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "[*] Starting MMR simulator on http://127.0.0.1:9090/ ..."
    Start-Process -FilePath $mmrExe -WorkingDirectory $root -WindowStyle Hidden
    Start-Sleep -Milliseconds 1200
} else {
    Write-Host "[*] MMR simulator already running."
}

Write-Host "[*] Starting web dashboard ..."
& $webExe
